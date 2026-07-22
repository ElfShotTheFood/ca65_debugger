import { DebugSession, InitializedEvent, OutputEvent, StoppedEvent, TerminatedEvent } from '@vscode/debugadapter';
import { DebugProtocol } from 'vscode-debugprotocol';
import { Socket } from 'net';
import { spawn, ChildProcess } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

interface DebugSpan {
    segmentId: number;
    offset: number;
}

interface SourceLine {
    fileId: string;
    line: number;
    spanId: number;
}

interface SourceLocation {
    path: string;
    line: number;
}

export class ViceDebugSession extends DebugSession {
    private viceProcess: ChildProcess | undefined;
    private socket: Socket | undefined;
    private connected = false;
    private readonly lineAddressMap = new Map<string, number>();
    private readonly addressSourceMap = new Map<number, SourceLocation>();
    private readonly armedBreakpointAddresses = new Set<number>();
    private readonly pendingCommands: string[] = [];
    private commandInFlight = false;
    private programToAutostart: string | undefined;
    private programStarted = false;
    private lastStoppedAddress: number | undefined;
    private stepInProgress = false;

    public constructor() {
        super();
        this.setDebuggerLinesStartAt1(true);
        this.setDebuggerColumnsStartAt1(true);
    }

    protected initializeRequest(response: DebugProtocol.InitializeResponse, _args: DebugProtocol.InitializeRequestArguments): void {
        response.body = {
            supportsConfigurationDoneRequest: true,
            supportsTerminateRequest: true
        };
        this.sendResponse(response);
        this.sendEvent(new InitializedEvent());
    }

    protected launchRequest(response: DebugProtocol.LaunchResponse, args: any): void {
        const vicePath = args.vicePath || 'xpet';
        const program = args.program as string;
        if (!program) {
            this.sendErrorResponse(response, 1001, 'A launch configuration must specify "program".');
            return;
        }

        try {
            const mappings = this.loadDebugSymbols(program);
            this.output(`Loaded ${mappings} source-to-address mappings.`);
            // Do not use VICE's -autostart option here. It starts the program
            // before DAP has supplied the breakpoints. configurationDoneRequest
            // will autostart only after setBreakPointsRequest has run.
            this.programToAutostart = program;
            this.viceProcess = spawn(vicePath, ['-remotemonitor']);
            this.viceProcess.once('error', error => this.output(`Unable to launch VICE: ${error.message}`, 'stderr'));
            this.viceProcess.once('exit', () => this.sendEvent(new TerminatedEvent()));
            this.output(`Launching VICE: ${vicePath}; program will autostart after breakpoints are configured: ${program}`);
            this.connectToVice(response, 0);
        } catch (error) {
            this.sendErrorResponse(response, 1002, `Unable to launch VICE: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    private connectToVice(response: DebugProtocol.LaunchResponse, attempt: number): void {
        const port = 6510;
        const socket = new Socket();
        this.socket = socket;

        socket.once('error', error => {
            socket.destroy();
            if (attempt < 19) {
                setTimeout(() => this.connectToVice(response, attempt + 1), 250);
                return;
            }
            this.sendErrorResponse(response, 1003, `Could not connect to the VICE monitor on port ${port}: ${error.message}`);
        });

        socket.connect(port, '127.0.0.1', () => {
            this.connected = true;
            socket.removeAllListeners('error');
            socket.on('error', error => this.output(`VICE monitor socket error: ${error.message}`, 'stderr'));
            socket.on('data', data => this.processViceResponse(data.toString()));
            socket.on('close', () => { this.connected = false; });
            this.output(`Connected to VICE remote monitor on port ${port}.`);
            this.flushPendingCommands();
            this.sendResponse(response);
        });
    }

    /**
     * The .dbg file puts line records before spans/segments.  Parse all records
     * first, then resolve source lines in a second pass.
     */
    private loadDebugSymbols(programPath: string): number {
        this.lineAddressMap.clear();
        this.addressSourceMap.clear();
        const dbgPath = programPath.replace(/\.[^/.]+$/, '.dbg');
        if (!fs.existsSync(dbgPath)) {
            this.output(`No .dbg file found beside program: ${dbgPath}`, 'stderr');
            return 0;
        }

        const files = new Map<string, string>();
        const segments = new Map<number, number>();
        const spans = new Map<number, DebugSpan>();
        const sourceLines: SourceLine[] = [];

        for (const record of fs.readFileSync(dbgPath, 'utf8').split(/\r?\n/)) {
            const kind = record.split('\t', 1)[0];
            const id = this.decimalField(record, 'id');
            if (kind === 'file' && id !== undefined) {
                const filename = /(?:^|,)name="([^"]+)"/.exec(record)?.[1];
                if (filename) files.set(String(id), path.basename(filename));
            } else if (kind === 'seg' && id !== undefined) {
                const start = this.hexField(record, 'start');
                if (start !== undefined) segments.set(id, start);
            } else if (kind === 'span' && id !== undefined) {
                const segmentId = this.decimalField(record, 'seg');
                const offset = this.decimalField(record, 'start');
                if (segmentId !== undefined && offset !== undefined) spans.set(id, { segmentId, offset });
            } else if (kind === 'line') {
                const fileId = this.decimalField(record, 'file');
                const line = this.decimalField(record, 'line');
                const spanId = this.decimalField(record, 'span');
                if (fileId !== undefined && line !== undefined && spanId !== undefined) sourceLines.push({ fileId: String(fileId), line, spanId });
            }
        }

        for (const sourceLine of sourceLines) {
            const filename = files.get(sourceLine.fileId);
            const span = spans.get(sourceLine.spanId);
            const segmentStart = span ? segments.get(span.segmentId) : undefined;
            if (filename && span && segmentStart !== undefined) {
                // ca65's .dbg line field matches the editor's one-based source line number.
                const address = segmentStart + span.offset;
                this.lineAddressMap.set(this.sourceKey(filename, sourceLine.line), address);
                this.addressSourceMap.set(address, {
                    path: path.join(path.dirname(programPath), filename),
                    line: sourceLine.line
                });
            }
        }
        return this.lineAddressMap.size;
    }

    private decimalField(record: string, field: string): number | undefined {
        const value = new RegExp(`(?:^|[\\t,])${field}=(\\d+)`).exec(record)?.[1];
        return value === undefined ? undefined : Number.parseInt(value, 10);
    }

    private hexField(record: string, field: string): number | undefined {
        const value = new RegExp(`(?:^|[\\t,])${field}=0x([0-9a-fA-F]+)`).exec(record)?.[1];
        return value === undefined ? undefined : Number.parseInt(value, 16);
    }

    // DebugSession's request dispatcher requires the capital-P method name.
    protected setBreakPointsRequest(response: DebugProtocol.SetBreakpointsResponse, args: DebugProtocol.SetBreakpointsArguments): void {
        const filename = args.source.path ? path.basename(args.source.path) : undefined;
        const requested = args.breakpoints ?? [];
        if (!filename) {
            this.sendErrorResponse(response, 1004, 'The breakpoint request did not include a source path.');
            return;
        }

        this.output(`setBreakPointsRequest: ${filename}; ${requested.length} requested breakpoint(s).`);
        response.body = {
            breakpoints: requested.map(breakpoint => {
                const key = this.sourceKey(filename, breakpoint.line);
                const address = this.lineAddressMap.get(key);
                if (address === undefined) {
                    this.output(`No address for ${key}; breakpoint will remain unverified.`, 'stderr');
                    return { verified: false, line: breakpoint.line, message: 'No executable address is available for this source line.' };
                }
                const command = `break $${address.toString(16).padStart(4, '0')}`;
                this.output(`Resolved ${key} to $${address.toString(16).padStart(4, '0')}.`);
                this.armedBreakpointAddresses.add(address);
                this.sendViceCommand(command);
                return { verified: true, line: breakpoint.line };
            })
        };
        this.sendResponse(response);
    }

    protected continueRequest(response: DebugProtocol.ContinueResponse, _args: DebugProtocol.ContinueArguments): void {
        this.sendViceCommand('g');
        this.sendResponse(response);
    }

    /** VICE monitor `z` executes one CPU instruction and returns to the prompt. */
    protected stepInRequest(response: DebugProtocol.StepInResponse, _args: DebugProtocol.StepInArguments): void {
        this.stepInProgress = true;
        this.sendViceCommand('z');
        this.sendResponse(response);
    }

    protected configurationDoneRequest(response: DebugProtocol.ConfigurationDoneResponse, _args: DebugProtocol.ConfigurationDoneArguments): void {
        this.sendResponse(response);
        if (!this.programStarted && this.programToAutostart) {
            this.programStarted = true;
            const escapedProgram = this.programToAutostart.replace(/"/g, '\\"');
            this.sendViceCommand(`autostart "${escapedProgram}"`);
        }
    }

    protected threadsRequest(response: DebugProtocol.ThreadsResponse): void {
        response.body = { threads: [{ id: 1, name: '6502' }] };
        this.sendResponse(response);
    }

    protected stackTraceRequest(response: DebugProtocol.StackTraceResponse, _args: DebugProtocol.StackTraceArguments): void {
        const location = this.lastStoppedAddress === undefined ? undefined : this.addressSourceMap.get(this.lastStoppedAddress);
        response.body = {
            stackFrames: location ? [{
                id: 1,
                name: `$${this.lastStoppedAddress!.toString(16).padStart(4, '0')}`,
                source: { name: path.basename(location.path), path: location.path },
                line: location.line,
                column: 1
            }] : [],
            totalFrames: location ? 1 : 0
        };
        this.sendResponse(response);
    }

    protected disconnectRequest(response: DebugProtocol.DisconnectResponse): void {
        this.socket?.destroy();
        this.viceProcess?.kill();
        this.sendResponse(response);
        this.sendEvent(new TerminatedEvent());
    }

    private sourceKey(filename: string, line: number): string {
        return `${filename.toLowerCase()}:${line}`;
    }

    private sendViceCommand(command: string): void {
        this.pendingCommands.push(command);
        if (!this.connected || !this.socket || this.commandInFlight) {
            this.output(`Queued VICE command: ${command}`);
            return;
        }
        this.flushPendingCommands();
    }

    private flushPendingCommands(): void {
        if (!this.connected || !this.socket || this.commandInFlight) return;

        const command = this.pendingCommands.shift();
        if (!command) return;

        this.commandInFlight = true;
        this.output(`VICE <= ${command}`);
        // The VICE text monitor is line-oriented and only reliably accepts the
        // next command once it has printed a prompt for the previous one.
        this.socket.write(`${command}\r\n`);
    }

    private processViceResponse(data: string): void {
        const text = data.trim();
        if (text) this.output(`VICE => ${text}`);
        // VICE emits an initial monitor prompt such as (C:$e118) when the
        // monitor opens. A prompt alone is not a DAP stop. Only report a
        // breakpoint stop when the shown PC is one of the addresses we armed.
        // BREAK: ... (Stop on exec) is the command acknowledgement, not a hit.
        const stoppedAt = /(?:\b|\()C:\$([0-9a-f]{4,6})\)/i.exec(data);
        if (stoppedAt) {
            // A monitor prompt means the preceding command has completed.
            this.commandInFlight = false;
        }
        if (stoppedAt && !/BREAK:\s*\d+.*Stop on exec/i.test(data)) {
            const address = Number.parseInt(stoppedAt[1], 16);
            if (this.stepInProgress) {
                this.stepInProgress = false;
                this.lastStoppedAddress = address;
                this.output(`VICE completed step at $${stoppedAt[1]}.`);
                this.sendEvent(new StoppedEvent('step', 1));
            } else if (this.armedBreakpointAddresses.has(address)) {
                this.lastStoppedAddress = address;
                this.output(`VICE hit breakpoint at $${stoppedAt[1]}.`);
                this.sendEvent(new StoppedEvent('breakpoint', 1));
            } else {
                this.output(`Ignoring monitor prompt at $${stoppedAt[1]}; it is not an armed source breakpoint.`);
            }
        }
        this.flushPendingCommands();
    }

    private output(message: string, category: 'stdout' | 'stderr' = 'stdout'): void {
        this.sendEvent(new OutputEvent(`${message}\n`, category));
    }
}

DebugSession.run(ViceDebugSession);
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
enum StepOutStage { Idle, ReadingLow, ReadingHigh, Armed }

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
    private stepOverState: { waitingForDisassembly: boolean; address: number; remaining: number } | undefined;
    private stepOutStage = StepOutStage.Idle;
    private temporaryBreakpoint: number | undefined;
    private stepOutLow: number | undefined;
    private stepOutLastAddr: number | undefined;
    private lastRegisters: { [key: string]: string } = {};

    public constructor() {
        super();
        this.setDebuggerLinesStartAt1(true);
        this.setDebuggerColumnsStartAt1(true);
    }

    protected initializeRequest(response: DebugProtocol.InitializeResponse, _args: DebugProtocol.InitializeRequestArguments): void {
        response.body = {
            supportsConfigurationDoneRequest: true,
            supportsTerminateRequest: true,
            supportsStepInTargetsRequest: true,
            supportsStepBack: false
        };
        this.sendResponse(response);
        this.sendEvent(new InitializedEvent());
    }

    protected dispatchRequest(request: DebugProtocol.Request): void {
        this.output(`DEBUG: PROTOCOL RECEIVED command=${request.command} args=${JSON.stringify(request.arguments)}`);
        
        if (request.command === 'next') {
            this.nextRequest(
                {
                    seq: 0,
                    type: 'response',
                    request_seq: request.seq,
                    success: true,
                    command: 'next',
                    message: '',
                    body: {}
                },
                request.arguments as DebugProtocol.NextArguments
            );
            return;
        }

        super.dispatchRequest(request);
    }

    protected scopesRequest(response: DebugProtocol.ScopesResponse, _args: DebugProtocol.ScopesArguments): void {
        response.body = {
            scopes: [
                { name: 'Registers', variablesReference: 1, expensive: false }
            ]
        };
        this.sendResponse(response);
    }

    protected variablesRequest(response: DebugProtocol.VariablesResponse, args: DebugProtocol.VariablesArguments): void {
        const variables: DebugProtocol.Variable[] = [];
        if (args.variablesReference === 1) {
            for (const [key, value] of Object.entries(this.lastRegisters)) {
                variables.push({ name: key, value: value, variablesReference: 0 });
            }
            if (this.lastStoppedAddress !== undefined) {
                variables.push({ name: 'PC', value: '$' + this.lastStoppedAddress.toString(16).padStart(4, '0'), variablesReference: 0 });
            }
        }
        response.body = { variables };
        this.sendResponse(response);
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

    protected stepInRequest(response: DebugProtocol.StepInResponse, _args: DebugProtocol.StepInArguments): void {
        this.output("DEBUG: StepInRequest RECEIVED");
        this.stepInProgress = true;
        this.sendViceCommand('z');
        this.sendResponse(response);
    }

    protected nextRequest(response: DebugProtocol.NextResponse, _args: DebugProtocol.NextArguments): void {
        this.output("DEBUG: NextRequest (Step Over) RECEIVED");
        this.stepInProgress = true;
        if (this.lastStoppedAddress !== undefined) {
            const pc = this.lastStoppedAddress;
            this.stepOverState = { waitingForDisassembly: true, address: pc, remaining: 1 };
            this.sendViceCommand(`m ${pc.toString(16).padStart(4, '0')} ${pc.toString(16).padStart(4, '0')}`);
        } else {
            this.sendViceCommand('z');
        }
        this.sendResponse(response);
    }

    protected stepOutRequest(response: DebugProtocol.StepOutResponse, _args: DebugProtocol.StepOutArguments): void {
        this.output("DEBUG: StepOutRequest RECEIVED");
        const spHex = this.lastRegisters['SP']?.replace('$', '');
        if (spHex) {
            const sp = parseInt(spHex, 16);
            const lowAddr = (0x0100 + sp + 1) & 0xFFFF;
            const highAddr = (0x0100 + sp + 2) & 0xFFFF;
            this.stepOutStage = StepOutStage.ReadingLow;
            this.stepOutLow = undefined;
            this.output(`Step Out: Reading return address from stack at $${lowAddr.toString(16)} and $${highAddr.toString(16)} (SP=$${spHex})`);
            this.sendViceCommand(`m ${lowAddr.toString(16).padStart(4, '0')} ${lowAddr.toString(16).padStart(4, '0')}`);
            this.sendViceCommand(`m ${highAddr.toString(16).padStart(4, '0')} ${highAddr.toString(16).padStart(4, '0')}`);
        } else {
            this.output("Step Out: Could not determine SP, falling back to step", 'stderr');
            this.sendViceCommand('z');
        }
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
        this.socket.write(`${command}\r\n`);
    }

    private processViceResponse(data: string): void {
        const lines = data.split('\n');
        for (const line of lines) {
            const text = line.trim();
            if (text) this.output(`VICE => ${text}`);
            const regMatch = /A:([0-9a-f]{2})\s+X:([0-9a-f]{2})\s+Y:([0-9a-f]{2})\s+SP:([0-9a-f]{2})/i.exec(text);
            if (regMatch) {
                this.lastRegisters = { A: '$' + regMatch[1], X: '$' + regMatch[2], Y: '$' + regMatch[3], SP: '$' + regMatch[4] };
            }
            const stoppedAt = /(?:\b|\()C:\$([0-9a-f]{4,6})\)/i.exec(text) || /^\.C:([0-9a-f]{4})/i.exec(text);
            if (stoppedAt) {
                this.commandInFlight = false;
                this.lastStoppedAddress = Number.parseInt(stoppedAt[1], 16);
            }

            if (this.stepOverState && this.stepOverState.waitingForDisassembly) {
                const memMatch = /^\s*>\s*[C:]{0,2}\s*[0-9a-f]{4}\s+([0-9a-f]{2})/i.exec(text);
                if (memMatch) {
                    const opcode = memMatch[1];
                    this.output(`DEBUG: memory read at PC $${this.stepOverState.address.toString(16)}: opcode $${opcode}`);

                    if (opcode === '20') {
                        const nextAddr = (this.lastStoppedAddress || 0) + 3;
                        this.output(`Step Over triggered: JSR ($20) detected, setting break at $${nextAddr.toString(16)} then continuing`);
                        this.sendViceCommand(`break $${nextAddr.toString(16)}`);
                        this.sendViceCommand('g');
                    } else {
                        this.output(`Step Over: No JSR, stepping.`);
                        this.sendViceCommand('z');
                    }
                    this.stepOverState = undefined;
                    this.flushPendingCommands();
                }
            }

            if (this.stepOutStage === StepOutStage.ReadingLow) {
                const memMatch = /^\s*>\s*[C:]{0,2}\s*[0-9a-f]{4}\s+([0-9a-f]{2})|^([0-9a-f]{2})\s*$/i.exec(text);
                if (memMatch) {
                    this.stepOutLow = parseInt(memMatch[1] || memMatch[2], 16);
                    this.output(`Step Out: Read low byte 0x${this.stepOutLow.toString(16)}`);
                    const sp = parseInt(this.lastRegisters['SP']?.replace('$', '') || '0', 16);
                    const highAddr = (0x0100 + sp + 2) & 0xFFFF;
                    this.stepOutStage = StepOutStage.ReadingHigh;
                    this.sendViceCommand(`m ${highAddr.toString(16).padStart(4, '0')} ${highAddr.toString(16).padStart(4, '0')}`);
                    this.flushPendingCommands();
                }
            } else if (this.stepOutStage === StepOutStage.ReadingHigh) {
                const memMatch = /^\s*>\s*[C:]{0,2}\s*[0-9a-f]{4}\s+([0-9a-f]{2})|^([0-9a-f]{2})\s*$/i.exec(text);
                if (memMatch) {
                    const val = parseInt(memMatch[1] || memMatch[2], 16);
                    const high = val;
                    const low = this.stepOutLow!;
                    this.stepOutLow = undefined;
                    
                    const retAddr = ((high << 8) | low) + 1;
                    const addrStr = retAddr.toString(16).padStart(4, '0');
                    this.output(`Step Out: Calculated return address $${addrStr} (from low $${low.toString(16)} and high $${high.toString(16)})`);
                    this.temporaryBreakpoint = retAddr;
                    this.stepOutStage = StepOutStage.Armed;
                    this.sendViceCommand(`break $${addrStr}`);
                    this.sendViceCommand('g');
                    this.flushPendingCommands();
                }
            }

            const bpMatch = /^(\d+)\.\s+Breakpoint at \$([0-9a-f]{4})/i.exec(text);
            if (bpMatch) {
                const id = bpMatch[1];
                const addr = bpMatch[2];
                if (this.temporaryBreakpoint !== undefined && addr === this.temporaryBreakpoint.toString(16).padStart(4, '0')) {
                    this.output(`Breakpoint: Deleting temporary ID ${id} at $${addr}`);
                    this.sendViceCommand(`del ${id}`);
                    this.temporaryBreakpoint = undefined;
                }
            }

            if (stoppedAt && !/BREAK:\s*\d+.*Stop on exec/i.test(text)) {
                const address = this.lastStoppedAddress!;
                if (this.stepInProgress) {
                    this.stepInProgress = false;
                    this.output(`VICE completed step at $${address.toString(16)}.`);
                    this.sendEvent(new StoppedEvent('step', 1));
                } else if (this.armedBreakpointAddresses.has(address)) {
                    this.output(`VICE hit breakpoint at $${address.toString(16)}.`);
                    if (this.temporaryBreakpoint === address) {
                        this.lastStoppedAddress = address;
                        this.sendViceCommand('breakpoints');
                    }
                    this.sendEvent(new StoppedEvent('breakpoint', 1));
                }
            } else if (stoppedAt && /BREAK:\s*\d+.*Stop on exec/i.test(text)) {
                this.sendViceCommand('g');
            }
        }
        this.flushPendingCommands();
    }

    private output(message: string, category: 'stdout' | 'stderr' = 'stdout'): void {
        this.sendEvent(new OutputEvent(`${message}\n`, category));
    }
}

DebugSession.run(ViceDebugSession);

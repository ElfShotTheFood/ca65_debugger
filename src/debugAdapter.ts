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
    private lastRegisters: { [key: string]: string } = {};
    /** Processor status (P) as a numeric byte, when known. */
    private lastP: number | undefined;
    private static readonly P_FLAGS_REF = 2;
    private static readonly FLAG_NAMES = ['N', 'V', '-', 'B', 'D', 'I', 'Z', 'C'] as const;

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
            supportsStepBack: false,
            supportsSetVariable: true
        };
        this.sendResponse(response);
        this.sendEvent(new InitializedEvent());
    }


    protected dispatchRequest(request: DebugProtocol.Request): void {
        this.output(`DEBUG: PROTOCOL RECEIVED command=${request.command} args=${JSON.stringify(request.arguments)}`);
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
            // Display order: PC, SP, A, X, Y, P
            if (this.lastStoppedAddress !== undefined) {
                variables.push({
                    name: 'PC',
                    value: '$' + this.lastStoppedAddress.toString(16).padStart(4, '0'),
                    variablesReference: 0,
                    type: 'register'
                });
            }
            for (const key of ['SP', 'A', 'X', 'Y'] as const) {
                const value = this.lastRegisters[key];
                if (value !== undefined) {
                    variables.push({ name: key, value, variablesReference: 0, type: 'register' });
                }
            }
            if (this.lastRegisters['P'] !== undefined || this.lastP !== undefined) {
                const p = this.normalizedP();
                if (p !== undefined) {
                    variables.push({
                        name: 'P',
                        value: '$' + p.toString(16).padStart(2, '0'),
                        variablesReference: ViceDebugSession.P_FLAGS_REF,
                        namedVariables: ViceDebugSession.FLAG_NAMES.length,
                        type: 'register'
                    });
                }
            }
        } else if (args.variablesReference === ViceDebugSession.P_FLAGS_REF) {
            const p = this.normalizedP() ?? 0x20;
            for (let i = 0; i < ViceDebugSession.FLAG_NAMES.length; i++) {
                const name = ViceDebugSession.FLAG_NAMES[i];
                const bit = 7 - i;
                // Unused bit 5 ('-') is always shown as 1 and is not meant to be edited.
                const set = name === '-' ? true : (p & (1 << bit)) !== 0;
                variables.push({
                    name,
                    value: set ? '1' : '0',
                    variablesReference: 0,
                    type: 'flag',
                    // Hint that '-' is not writable; setVariable still enforces this.
                    presentationHint: name === '-' ? { attributes: ['readOnly'] } : undefined
                });
            }
        }
        response.body = { variables };
        this.sendResponse(response);
    }

    protected setVariableRequest(response: DebugProtocol.SetVariableResponse, args: DebugProtocol.SetVariableArguments): void {
        try {
            if (args.variablesReference === 1) {
                this.setRegisterVariable(response, args.name, args.value);
                return;
            }
            if (args.variablesReference === ViceDebugSession.P_FLAGS_REF) {
                this.setFlagVariable(response, args.name, args.value);
                return;
            }
            this.sendErrorResponse(response, 1100, `Cannot set variable in scope ${args.variablesReference}.`);
        } catch (error) {
            this.sendErrorResponse(response, 1101, error instanceof Error ? error.message : String(error));
        }
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
        this.output("DEBUG: StepInRequest (z) RECEIVED");
        this.sendViceCommand('z');
        this.sendResponse(response);
    }

    protected nextRequest(response: DebugProtocol.NextResponse, _args: DebugProtocol.NextArguments): void {
        this.output("DEBUG: NextRequest (n) RECEIVED");
        this.sendViceCommand('n');
        this.sendResponse(response);
    }

    protected stepOutRequest(response: DebugProtocol.StepOutResponse, _args: DebugProtocol.StepOutArguments): void {
        this.output("DEBUG: StepOutRequest (return) RECEIVED");
        this.sendViceCommand('return');
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
            // Typical VICE stop line:
            //   .C:0401  A:00 X:00 Y:00 SP:f6 ..-...Z.  00 001014
            // or with letters for set flags / P hex:
            //   A:00 X:00 Y:00 SP:f6 P:30 NV-BDIZC
            const regMatch = /A:([0-9a-f]{2})\s+X:([0-9a-f]{2})\s+Y:([0-9a-f]{2})\s+SP:([0-9a-f]{2})(?:\s+(?:P:\$?([0-9a-f]{2})\s*)?([NVBDIZC.\-]{8}))?/i.exec(text);
            if (regMatch) {
                // Register dumps (including replies to `r ...=...`) should release the command queue
                // even when they are not a full "stopped" event.
                this.commandInFlight = false;
                this.lastRegisters = {
                    A: '$' + regMatch[1],
                    X: '$' + regMatch[2],
                    Y: '$' + regMatch[3],
                    SP: '$' + regMatch[4]
                };

                const pHex = regMatch[5];
                const flagStr = regMatch[6];
                if (pHex !== undefined) {
                    this.lastP = Number.parseInt(pHex, 16);
                } else if (flagStr !== undefined) {
                    this.lastP = this.flagsStringToByte(flagStr);
                } else {
                    // Fall back: some VICE builds print flags elsewhere on the line.
                    const looseFlags = /\s([NVBDIZC.\-]{8})(?:\s|$)/i.exec(text);
                    if (looseFlags) {
                        this.lastP = this.flagsStringToByte(looseFlags[1]);
                    }
                }
                if (this.lastP !== undefined) {
                    this.lastP = this.forceUnusedStatusBit(this.lastP);
                    this.lastRegisters['P'] = '$' + this.lastP.toString(16).padStart(2, '0');
                }
            } else {
                // Standalone P:xx if registers were already known
                const pOnly = /\bP:\$?([0-9a-f]{2})\b/i.exec(text);
                if (pOnly) {
                    this.lastP = this.forceUnusedStatusBit(Number.parseInt(pOnly[1], 16));
                    this.lastRegisters['P'] = '$' + this.lastP.toString(16).padStart(2, '0');
                }
            }

            const stoppedAt = /(?:\b|\()C:\$([0-9a-f]{4,6})\)/i.exec(text) || /^\.C:([0-9a-f]{4})/i.exec(text);
            if (stoppedAt) {
                this.commandInFlight = false;
                this.lastStoppedAddress = Number.parseInt(stoppedAt[1], 16);
                this.sendEvent(new StoppedEvent('step', 1));
            }
        }
        this.flushPendingCommands();
    }

    private output(message: string, category: 'stdout' | 'stderr' = 'stdout'): void {
        this.sendEvent(new OutputEvent(`${message}\n`, category));
    }

    /**
     * Convert a VICE NV-BDIZC flag string into a P status byte.
     * Set flags are shown as their letter (or '-' for bit 5); clear flags as '.'.
     */
    private flagsStringToByte(flagStr: string): number {
        let p = 0;
        const s = flagStr.toUpperCase();
        for (let i = 0; i < 8 && i < s.length; i++) {
            if (s[i] !== '.') {
                p |= (1 << (7 - i));
            }
        }
        return this.forceUnusedStatusBit(p);
    }

    /** Bit 5 of P is unused on 6502 and is kept hard-wired to 1. */
    private forceUnusedStatusBit(p: number): number {
        return (p & 0xff) | 0x20;
    }

    private normalizedP(): number | undefined {
        if (this.lastP !== undefined) {
            return this.forceUnusedStatusBit(this.lastP);
        }
        const raw = this.lastRegisters['P'];
        if (raw === undefined) {
            return undefined;
        }
        return this.forceUnusedStatusBit(this.parseInteger(raw, 0xff));
    }


    private setRegisterVariable(response: DebugProtocol.SetVariableResponse, name: string, rawValue: string): void {
        const reg = name.toUpperCase();
        if (reg === 'PC') {
            const value = this.parseInteger(rawValue, 0xffff);
            this.lastStoppedAddress = value;
            this.sendViceCommand(`r pc=$${value.toString(16).padStart(4, '0')}`);
            response.body = {
                value: '$' + value.toString(16).padStart(4, '0'),
                variablesReference: 0
            };
            this.sendResponse(response);
            return;
        }

        if (reg === 'A' || reg === 'X' || reg === 'Y' || reg === 'SP') {
            const value = this.parseInteger(rawValue, 0xff);
            const formatted = '$' + value.toString(16).padStart(2, '0');
            this.lastRegisters[reg] = formatted;
            const viceName = reg === 'SP' ? 'sp' : reg.toLowerCase();
            this.sendViceCommand(`r ${viceName}=$${value.toString(16).padStart(2, '0')}`);
            response.body = { value: formatted, variablesReference: 0 };
            this.sendResponse(response);
            return;
        }

        if (reg === 'P') {
            const value = this.forceUnusedStatusBit(this.parseInteger(rawValue, 0xff));
            this.applyLocalP(value);
            this.sendViceCommand(`r fl=$${value.toString(16).padStart(2, '0')}`);
            response.body = {
                value: '$' + value.toString(16).padStart(2, '0'),
                variablesReference: ViceDebugSession.P_FLAGS_REF,
                namedVariables: ViceDebugSession.FLAG_NAMES.length
            };
            this.sendResponse(response);
            return;
        }

        throw new Error(`Unknown register "${name}".`);
    }

    private setFlagVariable(response: DebugProtocol.SetVariableResponse, name: string, rawValue: string): void {
        const flag = name.toUpperCase() === '-' ? '-' : name.toUpperCase();
        if (flag === '-') {
            throw new Error('The unused status bit (-) is hard-wired to 1 and cannot be changed.');
        }

        const index = ViceDebugSession.FLAG_NAMES.indexOf(flag as typeof ViceDebugSession.FLAG_NAMES[number]);
        if (index < 0) {
            throw new Error(`Unknown flag "${name}".`);
        }

        const bitValue = this.parseFlagBit(rawValue);
        const bit = 7 - index;
        const current = this.normalizedP() ?? 0x20;
        const next = this.forceUnusedStatusBit(bitValue ? (current | (1 << bit)) : (current & ~(1 << bit)));
        this.applyLocalP(next);
        this.sendViceCommand(`r fl=$${next.toString(16).padStart(2, '0')}`);
        response.body = {
            value: bitValue ? '1' : '0',
            variablesReference: 0
        };
        this.sendResponse(response);
    }

    private applyLocalP(value: number): void {
        this.lastP = this.forceUnusedStatusBit(value);
        this.lastRegisters['P'] = '$' + this.lastP.toString(16).padStart(2, '0');
    }

    /** Accepts $ff, 0xff, ff, or decimal. */
    private parseInteger(rawValue: string, max: number): number {
        const text = rawValue.trim().toLowerCase();
        if (!text) {
            throw new Error('Value cannot be empty.');
        }

        let value: number;
        if (text.startsWith('$')) {
            value = Number.parseInt(text.slice(1), 16);
        } else if (text.startsWith('0x')) {
            value = Number.parseInt(text.slice(2), 16);
        } else if (/^[0-9a-f]+$/i.test(text) && /[a-f]/i.test(text)) {
            value = Number.parseInt(text, 16);
        } else if (/^\d+$/.test(text)) {
            value = Number.parseInt(text, 10);
        } else if (/^[0-9a-f]+$/i.test(text)) {
            // Pure hex digits with no prefix — treat as hex for register UX ($ omitted).
            value = Number.parseInt(text, 16);
        } else {
            throw new Error(`Invalid numeric value "${rawValue}". Use hex ($3a / 0x3a / 3a) or decimal.`);
        }

        if (!Number.isFinite(value) || value < 0 || value > max) {
            throw new Error(`Value "${rawValue}" is out of range (0..$${max.toString(16)}).`);
        }
        return value;
    }

    private parseFlagBit(rawValue: string): boolean {
        const text = rawValue.trim().toLowerCase();
        if (text === '1' || text === 'true' || text === 'on' || text === 'set') {
            return true;
        }
        if (text === '0' || text === 'false' || text === 'off' || text === 'clear') {
            return false;
        }
        throw new Error(`Invalid flag value "${rawValue}". Use 0 or 1.`);
    }
}


DebugSession.run(ViceDebugSession);

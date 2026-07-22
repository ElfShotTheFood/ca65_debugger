import * as vscode from 'vscode';

export function activate(context: vscode.ExtensionContext) {
    context.subscriptions.push(
        vscode.debug.registerDebugConfigurationProvider('vice', {
            resolveDebugConfiguration(folder, config, token) {
                if (!config.type && !config.request && !config.name) {
                    const editor = vscode.window.activeTextEditor;
                    if (editor && (editor.document.languageId === 'asm' || editor.document.languageId === 'ca65')) {
                        config.type = 'vice';
                        config.name = 'Launch VICE';
                        config.request = 'launch';
                        config.program = '${workspaceFolder}/${workspaceFolderBasename}.prg';
                    }
                }
                
                if (!config.program) {
                    return vscode.window.showErrorMessage("Please set a program to debug in launch.json").then(_ => {
                        return undefined;
                    });
                }
                return config;
            }
        })
    );
}

export function deactivate() {}

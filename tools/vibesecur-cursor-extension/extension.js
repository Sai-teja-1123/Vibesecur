// @ts-check
const vscode = require('vscode');
const path = require('path');
const { spawn } = require('child_process');

/**
 * Vibesecur monorepo root: tools/vibesecur-cursor-extension -> ../..
 */
function getVibesecurRoot() {
  return path.resolve(__dirname, '..', '..');
}

function getScanScriptPath() {
  return path.join(__dirname, 'run-repo-scan.mjs');
}

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
  const output = vscode.window.createOutputChannel('Vibesecur');
  const vibesecurRoot = getVibesecurRoot();
  const scanScript = getScanScriptPath();

  const runScan = async () => {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) {
      vscode.window.showWarningMessage('Vibesecur: open a folder workspace first.');
      return;
    }

    const repoRoot = folder.uri.fsPath;
    const maxFiles = String(
      vscode.workspace.getConfiguration('vibesecur').get('maxFiles') || 400,
    );

    output.clear();
    output.appendLine(`Vibesecur scan`);
    output.appendLine(`  workspace: ${repoRoot}`);
    output.appendLine(`  engine root: ${vibesecurRoot}`);
    output.appendLine(`  maxFiles: ${maxFiles}`);
    output.appendLine('');

    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Window,
        title: 'Vibesecur: scanning…',
      },
      async () => {
        await new Promise((resolve) => {
          const child = spawn(process.execPath, [scanScript], {
            cwd: vibesecurRoot,
            env: {
              ...process.env,
              VIBESECUR_ROOT: vibesecurRoot,
              REPO_ROOT: repoRoot,
              MAX_FILES: maxFiles,
            },
          });

          child.stdout.on('data', (d) => {
            output.append(d.toString());
          });
          child.stderr.on('data', (d) => {
            output.append(d.toString());
          });
          child.on('close', (code) => {
            if (code !== 0) {
              vscode.window.showErrorMessage(
                `Vibesecur scan failed (exit ${code}). See Output → Vibesecur.`,
              );
            } else {
              vscode.window.showInformationMessage(
                'Vibesecur scan finished. See Output → Vibesecur.',
              );
            }
            resolve(undefined);
          });
          child.on('error', (err) => {
            output.appendLine(String(err?.message || err));
            vscode.window.showErrorMessage(`Vibesecur scan could not start: ${err.message}`);
            resolve(undefined);
          });
        });
      },
    );

    output.show(true);
  };

  const copyMcpPrompt = async () => {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) {
      vscode.window.showWarningMessage('Vibesecur: open a folder workspace first.');
      return;
    }
    const repoRoot = folder.uri.fsPath.replace(/\\/g, '\\\\');
    const text = `Use MCP tool scanRepo with:\nrootPath: ${repoRoot}\nmaxFiles: 400`;
    await vscode.env.clipboard.writeText(text);
    vscode.window.showInformationMessage('Copied MCP scanRepo prompt to clipboard.');
  };

  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  status.text = '$(shield) Vibesecur';
  status.tooltip = 'Run Vibesecur security scan on this workspace';
  status.command = 'vibesecur.scanWorkspace';

  context.subscriptions.push(
    output,
    status,
    vscode.commands.registerCommand('vibesecur.scanWorkspace', runScan),
    vscode.commands.registerCommand('vibesecur.copyMcpPrompt', copyMcpPrompt),
  );

  status.show();
}

function deactivate() {}

module.exports = { activate, deactivate };

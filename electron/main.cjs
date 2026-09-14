const { app, BrowserWindow, dialog, ipcMain, protocol, session, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const http = require('http');
const { spawn } = require('child_process');

// ============================================================================
// 1. APPLICATION-SPECIFIC WRITABLE RUNTIME & CACHE CONFIGURATION
// ============================================================================
// Determine project root directory
let projectRoot = path.resolve(__dirname, '..');
if (!fs.existsSync(path.join(projectRoot, 'backend_fastapi')) && fs.existsSync(path.join(projectRoot, '..', 'backend_fastapi'))) {
  projectRoot = path.resolve(projectRoot, '..');
}

const runtimeDir = path.join(projectRoot, '.runtime', 'electron');
const userDataDir = path.join(runtimeDir, 'userData');
const diskCacheDir = path.join(runtimeDir, 'cache');
const gpuCacheDir = path.join(runtimeDir, 'gpu-cache');
const crashDumpsDir = path.join(runtimeDir, 'crashes');

// Ensure writable directories are created before any Chromium subsystem initializes
fs.mkdirSync(userDataDir, { recursive: true });
fs.mkdirSync(diskCacheDir, { recursive: true });
fs.mkdirSync(gpuCacheDir, { recursive: true });
fs.mkdirSync(crashDumpsDir, { recursive: true });

// Scope application identity and paths to project runtime directory
app.name = 'ForensiVault';
app.setPath('userData', userDataDir);
app.setPath('sessionData', userDataDir);
try {
  app.setPath('crashDumps', crashDumpsDir);
} catch (_) {}

// Configure Chromium CLI switches for writable cache directories
app.commandLine.appendSwitch('disk-cache-dir', diskCacheDir);
app.commandLine.appendSwitch('user-data-dir', userDataDir);
app.commandLine.appendSwitch('gpu-disk-cache-dir', gpuCacheDir);

if (process.platform === 'linux') {
  app.commandLine.appendSwitch('disable-features', 'Vulkan');
  app.commandLine.appendSwitch('disable-gpu-sandbox');
}

// Register file scheme privileges before app is ready
try {
  protocol.registerSchemesAsPrivileged([
    {
      scheme: 'file',
      privileges: {
        standard: true,
        secure: true,
        supportFetchAPI: true,
        corsEnabled: true
      }
    }
  ]);
} catch (_) {}

// ============================================================================
// 2. BACKEND LIFECYCLE & WINDOW CREATION
// ============================================================================
let mainWindow = null;
let backendProcess = null;

function checkUrlAvailable(url) {
  return new Promise((resolve) => {
    http.get(url, (res) => {
      resolve(res.statusCode >= 200 && res.statusCode < 400);
    }).on('error', () => {
      resolve(false);
    });
  });
}

function checkBackendElevated(port = 8766) {
  return new Promise((resolve) => {
    http.get(`http://127.0.0.1:${port}/api/system/privileges`, (res) => {
      if (res.statusCode !== 200) return resolve(false);
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve(Boolean(json && json.is_elevated));
        } catch (_) {
          resolve(false);
        }
      });
    }).on('error', () => {
      resolve(false);
    });
  });
}

function killProcessOnPort(port) {
  if (process.platform !== 'win32') return;
  try {
    const { execSync } = require('child_process');
    const out = execSync('netstat -ano -p tcp', { encoding: 'utf-8' });
    const lines = out.split('\n').filter(l => l.includes(`:${port}`) && l.includes('LISTENING'));
    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      const pid = parts[parts.length - 1];
      if (pid && !isNaN(pid) && parseInt(pid, 10) > 0) {
        console.log(`[Electron] Terminating unelevated backend PID ${pid} on port ${port}...`);
        try {
          execSync(`taskkill /F /PID ${pid}`, { stdio: 'ignore' });
        } catch (_) {}
      }
    }
  } catch (err) {
    console.warn(`[Electron] Error terminating process on port ${port}:`, err.message);
  }
}

function startBackendIfNeeded(isElevated = false) {
  return new Promise(async (resolve) => {
    let port = 8766;
    let isRunning = await checkUrlAvailable('http://127.0.0.1:8766/api/status');
    if (!isRunning) {
      const is8765Running = await checkUrlAvailable('http://127.0.0.1:8765/api/status');
      if (is8765Running) {
        port = 8765;
        isRunning = true;
      }
    }

    if (isRunning) {
      console.log(`[Electron] ForensiVault FastAPI backend is active on port ${port}.`);
      return resolve();
    }

    console.log(`[Electron] Starting ForensiVault FastAPI backend on port 8766 (${isElevated ? 'Elevated Administrator' : 'Standard User'})...`);
    const isWin = process.platform === 'win32';
    const pyCmd = isWin ? 'py' : 'python3';
    const pyArgs = isWin 
      ? ['-3', '-m', 'uvicorn', 'backend_fastapi.main:app', '--host', '127.0.0.1', '--port', '8766']
      : ['-m', 'uvicorn', 'backend_fastapi.main:app', '--host', '127.0.0.1', '--port', '8766'];

    backendProcess = spawn(pyCmd, pyArgs, {
      cwd: projectRoot,
      stdio: 'pipe',
      shell: true
    });

    backendProcess.stdout.on('data', (data) => {
      console.log(`[Backend] ${data.toString().trim()}`);
    });

    backendProcess.stderr.on('data', (data) => {
      console.error(`[Backend Err] ${data.toString().trim()}`);
    });

    let attempts = 0;
    const interval = setInterval(async () => {
      attempts++;
      const ok = await checkUrlAvailable('http://127.0.0.1:8765/api/status');
      if (ok || attempts > 20) {
        clearInterval(interval);
        console.log('[Electron] Backend startup verification completed.');
        resolve();
      }
    }, 500);
  });
}

function checkProcessElevated() {
  if (process.platform !== 'win32') return true;
  let elevateExe = path.join(__dirname, 'elevate.exe');
  if (!fs.existsSync(elevateExe)) {
    elevateExe = path.join(projectRoot, 'electron', 'elevate.exe');
  }
  if (fs.existsSync(elevateExe)) {
    try {
      const { execFileSync } = require('child_process');
      const out = execFileSync(elevateExe, ['--check-elevation'], { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] });
      const parsed = JSON.parse(out.trim());
      if (typeof parsed.is_elevated === 'boolean') {
        return parsed.is_elevated;
      }
    } catch (_) {}
  }
  try {
    const { execSync } = require('child_process');
    execSync('net session', { stdio: 'ignore' });
    return true;
  } catch (_) {}
  return false;
}

// Startup Marker (Requirement 9)
const initialElevated = checkProcessElevated();
console.log('[ELEVATION]');
console.log(`PID=${process.pid}`);
console.log('[ELEVATION]');
console.log(`Executable=${process.execPath}`);
console.log('[ELEVATION]');
console.log(`WorkingDirectory=${process.cwd()}`);
console.log('[ELEVATION]');
console.log(`IsElevated=${initialElevated}`);

async function createWindow() {
  const isElevated = checkProcessElevated();
  await startBackendIfNeeded(isElevated);

  if (isElevated) {
    console.log('[Electron] Process is running with Windows Administrator elevation.');
    // Signal handshake readiness if elevated (Requirement 10)
    const handshakePath = path.join(projectRoot, '.runtime', 'elevation_handshake.json');
    try {
      fs.writeFileSync(handshakePath, JSON.stringify({
        status: 'CONFIRMED',
        marker: 'FORENSIVAULT_ELEVATED_READY',
        pid: process.pid,
        is_elevated: true,
        timestamp: Date.now()
      }, null, 2));
      console.log('[Electron] Elevated handshake confirmed at:', handshakePath);
    } catch (err) {
      console.error('[Electron] Failed to write handshake confirmation:', err);
    }
  }

  // Allow local API communication for file:// origin without disabling webSecurity
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    const responseHeaders = Object.assign({}, details.responseHeaders);
    if (details.url.startsWith('http://127.0.0.1:8766') || details.url.startsWith('http://localhost:8766') ||
        details.url.startsWith('http://127.0.0.1:8765') || details.url.startsWith('http://localhost:8765')) {
      responseHeaders['access-control-allow-origin'] = ['*'];
      responseHeaders['access-control-allow-headers'] = ['*'];
      responseHeaders['access-control-allow-methods'] = ['GET, POST, PUT, DELETE, OPTIONS'];
    }
    callback({ responseHeaders });
  });

  mainWindow = new BrowserWindow({
    width: 1440,
    height: 920,
    minWidth: 1080,
    minHeight: 700,
    title: isElevated 
      ? 'ForensiVault - Professional Digital Forensics Workstation [Administrator (Elevated)]'
      : 'ForensiVault - Professional Digital Forensics Workstation',
    backgroundColor: '#FFF8EE',
    show: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: true // Security is fully preserved
    }
  });

  mainWindow.webContents.on('console-message', (event, level, message, line, sourceId) => {
    console.log(`[Renderer Console] ${message}`);
  });

  mainWindow.webContents.on('did-finish-load', () => {
    setTimeout(async () => {
      try {
        if (!mainWindow) return;
        const html = await mainWindow.webContents.executeJavaScript('document.getElementById("root") ? document.getElementById("root").innerHTML : document.body.innerHTML');
        console.log('[DOM CHECK] Root innerHTML length:', html ? html.length : 0);
        
        const img = await mainWindow.webContents.capturePage();
        const outPath = path.join(projectRoot, 'electron_screenshot.png');
        fs.writeFileSync(outPath, img.toPNG());
        console.log('[Electron] Live window screenshot captured to:', outPath);
      } catch (err) {
        console.error('[Electron] Capture error:', err);
      }
    }, 1500);
  });

  const devUrl = 'http://localhost:5173';
  const isDevRunning = await checkUrlAvailable(devUrl);

  if (isDevRunning) {
    console.log('[Electron] Loading React Vite dev server at', devUrl);
    await mainWindow.loadURL(devUrl);
  } else {
    const distPath = path.resolve(__dirname, '..', 'dist', 'index.html');
    const fallbackDist = path.resolve(projectRoot, 'frontend', 'dist', 'index.html');
    const targetFile = fs.existsSync(distPath) ? distPath : fallbackDist;
    console.log('[Electron] Loading built workstation UI from', targetFile);
    await mainWindow.loadFile(targetFile);
  }

  mainWindow.once('ready-to-show', () => {
    if (mainWindow) {
      mainWindow.show();
      mainWindow.focus();
    }
  });

  setTimeout(() => {
    if (mainWindow && !mainWindow.isVisible()) {
      mainWindow.show();
      mainWindow.focus();
    }
  }, 500);

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (backendProcess) {
    try {
      backendProcess.kill();
    } catch {}
  }
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

ipcMain.handle('desktop:ping', async () => {
  return { status: 'OK', workstation: 'ForensiVault Desktop Electron' };
});

ipcMain.handle('desktop:openPath', async (event, targetPath) => {
  if (!targetPath) return { success: false, error: 'Target path is required' };
  try {
    const fullPath = path.normalize(targetPath);
    if (!fs.existsSync(fullPath)) {
      return { success: false, error: `File not found: ${fullPath}` };
    }
    const errMsg = await shell.openPath(fullPath);
    if (errMsg) {
      return { success: false, error: errMsg };
    }
    return { success: true, path: fullPath };
  } catch (ex) {
    return { success: false, error: ex.message };
  }
});

ipcMain.handle('desktop:openReportPdf', async (event, targetPath) => {
  if (!targetPath) return { success: false, error: 'Target path is required' };
  try {
    const fullPath = path.resolve(path.normalize(String(targetPath).trim().replace(/^["']|["']$/g, '')));
    const allowedReportsDir = path.resolve(projectRoot, 'reports');

    // Security validation: restricted to ForensiVault reports directory
    if (!fullPath.toLowerCase().startsWith(allowedReportsDir.toLowerCase())) {
      return { success: false, error: 'Security restriction: Path must be inside ForensiVault reports directory.' };
    }
    if (path.extname(fullPath).toLowerCase() !== '.pdf') {
      return { success: false, error: 'Security restriction: Only PDF documents can be opened.' };
    }
    if (!fs.existsSync(fullPath)) {
      return { success: false, error: `Report PDF file not found: ${path.basename(fullPath)}` };
    }
    const stat = fs.statSync(fullPath);
    if (stat.size <= 0) {
      return { success: false, error: 'Report PDF is empty (0 bytes).' };
    }

    const errMsg = await shell.openPath(fullPath);
    if (errMsg) {
      return { success: false, error: `Failed to open PDF in default viewer: ${errMsg}` };
    }
    return { success: true, path: fullPath };
  } catch (ex) {
    return { success: false, error: ex.message };
  }
});

ipcMain.handle('desktop:openRecoveryFolder', async (event, targetPath) => {
  if (!targetPath) return { success: false, error: 'Target path is required' };
  try {
    const fullPath = path.resolve(path.normalize(String(targetPath).trim().replace(/^["']|["']$/g, '')));
    const allowedRec1 = path.resolve(projectRoot, 'ForensiVault_Recovered');
    const allowedRec2 = path.resolve(projectRoot, 'recovered');

    if (!fullPath.toLowerCase().startsWith(allowedRec1.toLowerCase()) &&
        !fullPath.toLowerCase().startsWith(allowedRec2.toLowerCase())) {
      return { success: false, error: 'Security restriction: Path must be inside ForensiVault recovery directory.' };
    }
    if (!fs.existsSync(fullPath)) {
      return { success: false, error: `Recovery folder not found: ${fullPath}` };
    }
    const stat = fs.statSync(fullPath);
    if (!stat.isDirectory()) {
      return { success: false, error: 'Target path is not a directory.' };
    }

    const errMsg = await shell.openPath(fullPath);
    if (errMsg) {
      return { success: false, error: `Failed to open folder in File Explorer: ${errMsg}` };
    }
    return { success: true, path: fullPath };
  } catch (ex) {
    return { success: false, error: ex.message };
  }
});

ipcMain.handle('desktop:selectEvidenceFile', async (event) => {
  try {
    const result = await dialog.showOpenDialog({
      title: 'Select Forensic Evidence Image (.img, .dd, .raw, .bin)',
      properties: ['openFile'],
      filters: [
        { name: 'Forensic Disk Images (*.img, *.dd, *.raw, *.bin)', extensions: ['img', 'dd', 'raw', 'bin'] },
        { name: 'All Files (*.*)', extensions: ['*'] }
      ]
    });
    if (result.canceled || !result.filePaths || result.filePaths.length === 0) {
      return { canceled: true, filePath: null };
    }
    return { canceled: false, filePath: result.filePaths[0] };
  } catch (ex) {
    return { canceled: true, error: ex.message };
  }
});

ipcMain.handle('desktop:getPrivileges', async () => {
  if (process.platform !== 'win32') {
    return {
      is_elevated: true,
      privilege_status: 'ELEVATED',
      elevation_level: 'Administrator',
      elevation_display: 'Administrator (Elevated)',
      pid: process.pid,
      executable: process.execPath,
      working_directory: process.cwd()
    };
  }
  try {
    const isElevated = checkProcessElevated();
    return {
      is_elevated: isElevated,
      privilege_status: isElevated ? 'ELEVATED' : 'NOT_ELEVATED',
      elevation_level: isElevated ? 'Administrator' : 'Standard User',
      elevation_display: isElevated ? 'Administrator (Elevated)' : 'Standard User (Restricted)',
      pid: process.pid,
      executable: process.execPath,
      working_directory: process.cwd()
    };
  } catch (ex) {
    return {
      is_elevated: false,
      privilege_status: 'NOT_ELEVATED',
      elevation_level: 'Standard User',
      elevation_display: 'Standard User (Restricted)',
      pid: process.pid,
      executable: process.execPath,
      working_directory: process.cwd(),
      error: ex.message
    };
  }
});

ipcMain.handle('desktop:getElevationState', async () => {
  const statePath = path.join(projectRoot, '.runtime', 'elevation_state.json');
  if (fs.existsSync(statePath)) {
    try {
      const content = fs.readFileSync(statePath, 'utf-8');
      const data = JSON.parse(content);
      // Clean up after consuming so state doesn't persist across future runs
      try { fs.unlinkSync(statePath); } catch (_) {}
      return data;
    } catch (_) {}
  }
  return null;
});

ipcMain.handle('desktop:relaunchElevated', async (event, stateData) => {
  if (process.platform !== 'win32') {
    return { success: false, message: 'Elevation relaunch is only supported on Windows.' };
  }

  const handshakePath = path.join(projectRoot, '.runtime', 'elevation_handshake.json');
  const statePath = path.join(projectRoot, '.runtime', 'elevation_state.json');

  // Clean any stale handshake file
  try {
    if (fs.existsSync(handshakePath)) fs.unlinkSync(handshakePath);
  } catch (_) {}

  // Save current workstation state (selected source, case id, route)
  try {
    const payload = typeof stateData === 'object' && stateData !== null ? stateData : { target_source: stateData };
    fs.writeFileSync(statePath, JSON.stringify({
      ...payload,
      timestamp: Date.now()
    }, null, 2));
  } catch (err) {
    console.warn('[Elevation] Failed to write state file:', err);
  }

  // Locate elevate.exe
  let elevateExe = path.join(__dirname, 'elevate.exe');
  if (!fs.existsSync(elevateExe)) {
    elevateExe = path.join(projectRoot, 'electron', 'elevate.exe');
  }

  // Determine correct binary, arguments, and working directory
  const isPackaged = app.isPackaged;
  let targetExe;
  let targetCwd = projectRoot;
  let targetArgs = [];

  const batLauncher = path.join(projectRoot, 'run_forensivault_desktop.bat');

  if (isPackaged) {
    targetExe = process.execPath;
    targetCwd = path.dirname(process.execPath);
    targetArgs = ['--elevated'];
  } else if (fs.existsSync(batLauncher)) {
    // Development mode with standard batch launcher:
    // elevate.exe automatically wraps .bat in cmd.exe /c
    targetExe = batLauncher;
    targetCwd = projectRoot;
    targetArgs = ['--elevated'];
  } else {
    // Development mode fallback (direct electron runtime)
    targetExe = process.execPath;
    targetCwd = projectRoot;
    const mainScript = path.resolve(__filename);
    targetArgs = [mainScript, '--elevated'];
  }

  console.log('[Elevation] Requesting elevation launcher:');
  console.log(`  Elevate Binary: ${elevateExe}`);
  console.log(`  Target Executable: ${targetExe}`);
  console.log(`  Working Directory: ${targetCwd}`);
  console.log(`  Target Arguments: ${targetArgs.join(' ')}`);

  return new Promise((resolve) => {
    if (!fs.existsSync(elevateExe)) {
      console.error('[Elevation] elevate.exe binary not found at:', elevateExe);
      return resolve({
        success: false,
        cancelled: false,
        message: 'ForensiVault could not start with Administrator privileges: elevate.exe missing.'
      });
    }

    let elevateOut = '';
    let elevateErr = '';

    const elevateProc = spawn(elevateExe, [targetExe, targetCwd, ...targetArgs], {
      cwd: projectRoot,
      windowsHide: false
    });

    elevateProc.stdout.on('data', (d) => {
      const str = d.toString();
      elevateOut += str;
      console.log(`[Elevate] ${str.trim()}`);
    });

    elevateProc.stderr.on('data', (d) => {
      const str = d.toString();
      elevateErr += str;
      console.error(`[Elevate Err] ${str.trim()}`);
    });

    elevateProc.on('error', (err) => {
      console.error('[Elevation] Failed to execute elevate.exe:', err);
      return resolve({
        success: false,
        cancelled: false,
        message: `ForensiVault could not start with Administrator privileges: ${err.message}`
      });
    });

    elevateProc.on('close', (code) => {
      console.log(`[Elevation] elevate.exe exited with code ${code}`);

      // Check for user cancellation (ERROR_CANCELLED = 1223)
      const isCancelled = code === 1223 || 
                          elevateOut.includes('STATUS:CANCELLED') || 
                          elevateOut.includes('user_cancelled=true') ||
                          elevateOut.includes('canceled by the user') ||
                          elevateOut.includes('cancelled by the user') ||
                          elevateOut.includes('CODE:1223');

      if (isCancelled) {
        console.log('[Elevation] Administrator elevation was cancelled by user (Exit code 1223).');
        try {
          if (fs.existsSync(statePath)) fs.unlinkSync(statePath);
        } catch (_) {}
        return resolve({
          success: false,
          cancelled: true,
          message: 'Administrator elevation was cancelled. ForensiVault will continue running as Standard User.'
        });
      }

      // Check for launch failure
      const isSuccess = code === 0 && (elevateOut.includes('STATUS:SUCCESS') || elevateOut.includes('PID:'));

      if (!isSuccess) {
        console.error(`[Elevation] Elevation launcher failed with exit code ${code}:`, elevateOut || elevateErr);
        try {
          if (fs.existsSync(statePath)) fs.unlinkSync(statePath);
        } catch (_) {}
        return resolve({
          success: false,
          cancelled: false,
          message: 'ForensiVault could not start with Administrator privileges.'
        });
      }

      // UAC accepted! Elevated process started.
      console.log('[Elevation] Elevated process launched. Awaiting startup handshake confirmation...');

      let pollAttempts = 0;
      const pollInterval = setInterval(() => {
        pollAttempts++;
        if (fs.existsSync(handshakePath)) {
          try {
            const data = JSON.parse(fs.readFileSync(handshakePath, 'utf-8'));
            if (data && data.status === 'CONFIRMED' && data.marker === 'FORENSIVAULT_ELEVATED_READY' && data.is_elevated) {
              clearInterval(pollInterval);
              console.log('[Elevation] Elevated instance confirmed startup (PID ' + data.pid + '). Handing over cleanly.');

              // Clean up handshake
              try { fs.unlinkSync(handshakePath); } catch (_) {}

              // IMPORTANT: Disown backendProcess so standard instance closing does not kill uvicorn
              if (backendProcess) {
                backendProcess = null;
              }

              // Gracefully close standard instance after brief delay to let elevated window appear
              setTimeout(() => {
                app.quit();
              }, 800);

              return resolve({
                success: true,
                status: 'ELEVATED_ACTIVE',
                message: 'ForensiVault relaunched as Administrator successfully.'
              });
            }
          } catch (_) {}
        }

        if (pollAttempts >= 60) { // 30 seconds
          clearInterval(pollInterval);
          console.warn('[Elevation] Handshake timed out after 30s. Standard instance remains open.');
          return resolve({
            success: false,
            cancelled: false,
            message: 'Elevated process startup verification timed out. ForensiVault will continue running as Standard User.'
          });
        }
      }, 500);
    });
  });
});



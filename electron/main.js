const { app, BrowserWindow, ipcMain, protocol, session, shell } = require('electron');
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

function startBackendIfNeeded() {
  return new Promise(async (resolve) => {
    const isRunning = await checkUrlAvailable('http://127.0.0.1:8765/api/status');
    if (isRunning) {
      console.log('[Electron] ForensiVault FastAPI backend is active on port 8765.');
      return resolve();
    }

    console.log('[Electron] Starting ForensiVault FastAPI backend on port 8765...');
    const isWin = process.platform === 'win32';
    const pyCmd = isWin ? 'py' : 'python3';
    const pyArgs = isWin 
      ? ['-3', '-m', 'uvicorn', 'backend_fastapi.main:app', '--host', '127.0.0.1', '--port', '8765']
      : ['-m', 'uvicorn', 'backend_fastapi.main:app', '--host', '127.0.0.1', '--port', '8765'];

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

async function createWindow() {
  await startBackendIfNeeded();

  // Allow local API communication for file:// origin without disabling webSecurity
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    const responseHeaders = Object.assign({}, details.responseHeaders);
    if (details.url.startsWith('http://127.0.0.1:8765') || details.url.startsWith('http://localhost:8765')) {
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
    title: 'ForensiVault - Professional Digital Forensics Workstation',
    backgroundColor: '#121110',
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

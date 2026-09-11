const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const http = require('http');

let mainWindow = null;

function checkUrlAvailable(url) {
  return new Promise((resolve) => {
    http.get(url, (res) => {
      resolve(res.statusCode >= 200 && res.statusCode < 400);
    }).on('error', () => {
      resolve(false);
    });
  });
}

async function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1100,
    minHeight: 700,
    title: 'ForensiVault - Professional Forensic Workstation',
    backgroundColor: '#F7F2E8',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  const devUrl = 'http://localhost:5173';
  const isDevRunning = await checkUrlAvailable(devUrl);

  if (isDevRunning) {
    console.log('[Electron] Loading React Vite dev server at', devUrl);
    await mainWindow.loadURL(devUrl);
  } else {
    const distPath = path.join(__dirname, '..', 'frontend', 'dist', 'index.html');
    console.log('[Electron] Loading built frontend from', distPath);
    await mainWindow.loadFile(distPath);
  }

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
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

ipcMain.handle('desktop:ping', async () => {
  return { status: 'OK', engine: 'ForensiVault Desktop Electron Workstation' };
});

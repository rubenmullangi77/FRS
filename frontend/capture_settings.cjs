const { app, BrowserWindow } = require('electron');
const path = require('path');
const fs = require('fs');

const projectRoot = path.resolve(__dirname, '..');
const runtimeDir = path.join(projectRoot, '.runtime', 'electron');
const userDataDir = path.join(runtimeDir, 'userData');
const diskCacheDir = path.join(runtimeDir, 'cache');
const gpuCacheDir = path.join(runtimeDir, 'gpu-cache');

fs.mkdirSync(userDataDir, { recursive: true });
fs.mkdirSync(diskCacheDir, { recursive: true });
fs.mkdirSync(gpuCacheDir, { recursive: true });

app.setPath('userData', userDataDir);
app.commandLine.appendSwitch('disk-cache-dir', diskCacheDir);
app.commandLine.appendSwitch('user-data-dir', userDataDir);
app.commandLine.appendSwitch('gpu-disk-cache-dir', gpuCacheDir);

const artifactDir = 'C:\\Users\\HP\\.gemini\\antigravity\\brain\\6f7202ef-c64a-477d-9f25-7c553ffbba2a';

async function run() {
  await app.whenReady();

  const win = new BrowserWindow({
    width: 1440,
    height: 960,
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'electron', 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: true
    }
  });

  const distPath = path.resolve(__dirname, 'dist', 'index.html');
  console.log('Loading app...');
  await win.loadFile(distPath);

  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  await wait(1500);

  // Auto-login by setting authenticated session in localStorage
  await win.webContents.executeJavaScript(`
    localStorage.setItem('forensivault_auth_session_v1', JSON.stringify({
      isAuthenticated: true,
      user: { username: 'Ruben', role: 'Lead Forensic Examiner' },
      token: 'mock-token-sih-2026'
    }));
    // Set theme to dark
    localStorage.setItem('forensivault_theme_mode', 'dark');
    document.documentElement.classList.add('dark');
    document.documentElement.setAttribute('data-theme', 'dark');
    window.location.reload();
  `);
  await wait(2000);

  // Navigate to Settings
  console.log('Navigating to settings...');
  await win.webContents.executeJavaScript(`
    // Find sidebar Settings tab button
    const buttons = Array.from(document.querySelectorAll('nav button, button'));
    const btn = buttons.find(b => b.textContent && b.textContent.includes('Settings'));
    if (btn) btn.click();
  `);
  await wait(1500);

  // Capture Settings (Dark)
  console.log('Capturing settings_dark.png...');
  let img = await win.webContents.capturePage();
  fs.writeFileSync(path.join(artifactDir, 'settings_dark.png'), img.toPNG());

  // Click Warm Cream Card
  console.log('Switching to Warm Cream...');
  await win.webContents.executeJavaScript(`
    // Click on the Warm Cream card
    const cards = Array.from(document.querySelectorAll('.workstation-card, div'));
    const creamCard = cards.find(c => c.textContent && c.textContent.includes('Warm Cream') && c.textContent.includes('Editorial'));
    if (creamCard) creamCard.click();
  `);
  await wait(1500);

  // Capture Settings (Light)
  console.log('Capturing settings_light.png...');
  img = await win.webContents.capturePage();
  fs.writeFileSync(path.join(artifactDir, 'settings_light.png'), img.toPNG());

  // Click Dark Mode Card again
  console.log('Switching back to Dark Mode...');
  await win.webContents.executeJavaScript(`
    const cards = Array.from(document.querySelectorAll('.workstation-card, div'));
    const darkCard = cards.find(c => c.textContent && c.textContent.includes('Dark Mode') && c.textContent.includes('Obsidian'));
    if (darkCard) darkCard.click();
  `);
  await wait(1000);

  console.log('Done captures!');
  app.quit();
}

run().catch((e) => {
  console.error(e);
  app.quit();
});

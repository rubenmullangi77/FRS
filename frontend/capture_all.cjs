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
  console.log('Loading app for Settings & Login visual verification...');
  await win.loadFile(distPath);

  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  await wait(1000);

  // 1. Authenticate user and go to settings in Dark Mode
  await win.webContents.executeJavaScript(`(() => {
    localStorage.setItem('forensivault_auth_session_v1', JSON.stringify({
      isAuthenticated: true,
      user: { username: 'Ruben', role: 'Lead Forensic Examiner' },
      token: 'mock-token'
    }));
    localStorage.setItem('forensivault_theme_mode', 'dark');
    document.documentElement.classList.add('dark');
    document.documentElement.setAttribute('data-theme', 'dark');
    window.location.reload();
  })()`);
  await wait(1500);

  // Navigate to Settings
  await win.webContents.executeJavaScript(`(() => {
    const sBtn = Array.from(document.querySelectorAll('button')).find(b => b.textContent && b.textContent.includes('Settings'));
    if (sBtn) sBtn.click();
  })()`);
  await wait(1200);

  // Capture Settings (Dark)
  console.log('Capturing settings_dark.png...');
  let img = await win.webContents.capturePage();
  fs.writeFileSync(path.join(artifactDir, 'settings_dark.png'), img.toPNG());

  // Click Warm Cream Card
  console.log('Clicking #theme-btn-light in Settings...');
  const lightResult = await win.webContents.executeJavaScript(`(() => {
    const lightCard = document.getElementById('theme-btn-light');
    if (lightCard) {
      lightCard.click();
      return { clicked: true, themeAttr: document.documentElement.getAttribute('data-theme'), isDark: document.documentElement.classList.contains('dark') };
    }
    return { clicked: false };
  })()`);
  console.log('Light switch result:', JSON.stringify(lightResult));
  await wait(1200);

  // Capture Settings (Light)
  console.log('Capturing settings_light.png...');
  img = await win.webContents.capturePage();
  fs.writeFileSync(path.join(artifactDir, 'settings_light.png'), img.toPNG());

  // Switch back to Dark in Settings
  await win.webContents.executeJavaScript(`(() => {
    const darkCard = document.getElementById('theme-btn-dark');
    if (darkCard) darkCard.click();
  })()`);
  await wait(800);

  // 2. Test Login Screen Visuals
  // Log out first
  await win.webContents.executeJavaScript(`(() => {
    localStorage.removeItem('forensivault_auth_session_v1');
    sessionStorage.removeItem('forensivault_auth_session_v1');
    localStorage.setItem('forensivault_theme_mode', 'dark');
    document.documentElement.classList.add('dark');
    document.documentElement.setAttribute('data-theme', 'dark');
    window.location.reload();
  })()`);
  await wait(1500);

  // Capture Login Screen (Dark)
  console.log('Capturing login_screen_dark.png...');
  img = await win.webContents.capturePage();
  fs.writeFileSync(path.join(artifactDir, 'login_screen_dark.png'), img.toPNG());

  // Click theme toggle on login screen
  console.log('Clicking #login-theme-toggle...');
  const toggleResult = await win.webContents.executeJavaScript(`(() => {
    const tBtn = document.getElementById('login-theme-toggle');
    if (tBtn) {
      tBtn.click();
      return { clicked: true, themeAttr: document.documentElement.getAttribute('data-theme'), isDark: document.documentElement.classList.contains('dark') };
    }
    return { clicked: false };
  })()`);
  console.log('Login toggle result:', JSON.stringify(toggleResult));
  await wait(1000);

  // Capture Login Screen (Light)
  console.log('Capturing login_screen_light.png...');
  img = await win.webContents.capturePage();
  fs.writeFileSync(path.join(artifactDir, 'login_screen_light.png'), img.toPNG());

  console.log('All verification captures finished successfully!');
  app.quit();
}

run().catch((e) => {
  console.error('Execution error:', e);
  app.quit();
});

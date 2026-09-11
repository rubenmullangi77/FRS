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
  await win.loadFile(distPath);

  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  await wait(1000);

  // ==========================================
  // 1. ENSURE LOGGED OUT STATE & DARK THEME
  // ==========================================
  await win.webContents.executeJavaScript(`(() => {
    localStorage.removeItem('forensivault_auth_session_v1');
    sessionStorage.removeItem('forensivault_auth_session_v1');
    localStorage.setItem('forensivault_theme_mode', 'dark');
    document.documentElement.classList.add('dark');
    document.documentElement.setAttribute('data-theme', 'dark');
    window.location.reload();
  })()`);
  await wait(1500);

  // Capture Login Screen (Dark Mode)
  console.log('1. Capturing login_dark_final.png...');
  let img = await win.webContents.capturePage();
  fs.writeFileSync(path.join(artifactDir, 'login_dark_final.png'), img.toPNG());

  // Toggle Theme on Login Screen to Warm Cream
  console.log('2. Toggling theme to Light on Login Screen...');
  const loginToggleRes = await win.webContents.executeJavaScript(`(() => {
    const btn = document.getElementById('login-theme-toggle');
    if (btn) {
      btn.click();
      return {
        clicked: true,
        themeAttr: document.documentElement.getAttribute('data-theme'),
        isDark: document.documentElement.classList.contains('dark'),
        bodyBg: window.getComputedStyle(document.body).backgroundColor
      };
    }
    return { clicked: false };
  })()`);
  console.log('Login toggle result:', JSON.stringify(loginToggleRes));
  await wait(1000);

  // Capture Login Screen (Light Mode)
  console.log('3. Capturing login_light_final.png...');
  img = await win.webContents.capturePage();
  fs.writeFileSync(path.join(artifactDir, 'login_light_final.png'), img.toPNG());

  // Toggle back to Dark mode on Login screen
  await win.webContents.executeJavaScript(`(() => {
    const btn = document.getElementById('login-theme-toggle');
    if (btn) btn.click();
  })()`);
  await wait(500);

  // ==========================================
  // 2. LOG IN TO WORKSTATION
  // ==========================================
  console.log('4. Logging in via Quick Demo credentials...');
  await win.webContents.executeJavaScript(`(() => {
    const autofill = document.querySelector('div[title*="examiner credentials"]');
    if (autofill) autofill.click();
    const submitBtn = document.querySelector('button[type="submit"]');
    if (submitBtn) submitBtn.click();
  })()`);
  await wait(2000);

  // ==========================================
  // 3. NAVIGATE TO SETTINGS PAGE
  // ==========================================
  console.log('5. Navigating to Settings page via #nav-settings...');
  const navRes = await win.webContents.executeJavaScript(`(() => {
    const navBtn = document.getElementById('nav-settings');
    if (navBtn) {
      navBtn.click();
      return { clicked: true };
    }
    return { clicked: false };
  })()`);
  console.log('Navigation result:', JSON.stringify(navRes));
  await wait(1500);

  // Capture Settings Page (Dark Mode)
  console.log('6. Capturing settings_dark_final.png...');
  img = await win.webContents.capturePage();
  fs.writeFileSync(path.join(artifactDir, 'settings_dark_final.png'), img.toPNG());

  // ==========================================
  // 4. TEST THEME SELECTION IN SETTINGS
  // ==========================================
  console.log('7. Clicking #theme-btn-light in Settings...');
  const settingsSwitchRes = await win.webContents.executeJavaScript(`(() => {
    const lightCard = document.getElementById('theme-btn-light');
    if (lightCard) {
      lightCard.click();
      return {
        clicked: true,
        themeAttr: document.documentElement.getAttribute('data-theme'),
        isDark: document.documentElement.classList.contains('dark'),
        bodyBg: window.getComputedStyle(document.body).backgroundColor
      };
    }
    return { clicked: false };
  })()`);
  console.log('Settings Light switch result:', JSON.stringify(settingsSwitchRes));
  await wait(1200);

  // Capture Settings Page (Warm Cream Light Mode)
  console.log('8. Capturing settings_light_final.png...');
  img = await win.webContents.capturePage();
  fs.writeFileSync(path.join(artifactDir, 'settings_light_final.png'), img.toPNG());

  console.log('All final verification captures completed!');
  app.quit();
}

run().catch((e) => {
  console.error('Final verification error:', e);
  app.quit();
});

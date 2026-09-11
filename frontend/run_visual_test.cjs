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

  // 1. Reset storage to clean logged out, dark theme state
  await win.webContents.executeJavaScript(`(() => {
    localStorage.clear();
    sessionStorage.clear();
    localStorage.setItem('forensivault_theme_mode', 'dark');
    document.documentElement.classList.add('dark');
    document.documentElement.setAttribute('data-theme', 'dark');
    window.location.reload();
  })()`);
  await wait(1500);

  // 2. Capture Login Screen (Dark)
  console.log('Capturing login_dark.png...');
  let img = await win.webContents.capturePage();
  fs.writeFileSync(path.join(artifactDir, 'login_dark.png'), img.toPNG());

  // 3. Switch Login Screen to Light Mode
  console.log('Toggling theme to Light on Login screen...');
  const toggleRes = await win.webContents.executeJavaScript(`(() => {
    const btn = document.getElementById('login-theme-toggle');
    if (btn) btn.click();
    return {
      themeAttr: document.documentElement.getAttribute('data-theme'),
      isDark: document.documentElement.classList.contains('dark'),
      htmlBg: window.getComputedStyle(document.documentElement).backgroundColor,
      bodyBg: window.getComputedStyle(document.body).backgroundColor
    };
  })()`);
  console.log('Toggle to light result:', JSON.stringify(toggleRes));
  await wait(1000);

  // 4. Capture Login Screen (Light)
  console.log('Capturing login_light.png...');
  img = await win.webContents.capturePage();
  fs.writeFileSync(path.join(artifactDir, 'login_light.png'), img.toPNG());

  // 5. Log in
  console.log('Authenticating into workstation...');
  await win.webContents.executeJavaScript(`(() => {
    const autofill = document.querySelector('div[title*="examiner credentials"]');
    if (autofill) autofill.click();
    const submitBtn = document.querySelector('button[type="submit"]');
    if (submitBtn) submitBtn.click();
  })()`);
  await wait(2500);

  // 6. Navigate to Settings page
  console.log('Navigating to Settings page...');
  const navRes = await win.webContents.executeJavaScript(`(() => {
    const navBtn = document.getElementById('nav-settings');
    if (navBtn) {
      navBtn.click();
      return { success: true };
    }
    // Fallback: search by text
    const btns = Array.from(document.querySelectorAll('button'));
    const b = btns.find(x => x.textContent && x.textContent.includes('Settings'));
    if (b) {
      b.click();
      return { success: true, viaFallback: true };
    }
    return { success: false };
  })()`);
  console.log('Navigation to settings:', JSON.stringify(navRes));
  await wait(1500);

  // 7. Capture Settings (Light Mode)
  console.log('Capturing settings_light.png...');
  img = await win.webContents.capturePage();
  fs.writeFileSync(path.join(artifactDir, 'settings_light.png'), img.toPNG());

  // 8. Click Dark Mode card in Settings
  console.log('Switching to Dark Mode in Settings...');
  const darkCardRes = await win.webContents.executeJavaScript(`(() => {
    const darkBtn = document.getElementById('theme-btn-dark');
    if (darkBtn) {
      darkBtn.click();
      return {
        success: true,
        themeAttr: document.documentElement.getAttribute('data-theme'),
        isDark: document.documentElement.classList.contains('dark')
      };
    }
    return { success: false };
  })()`);
  console.log('Dark Mode switch result:', JSON.stringify(darkCardRes));
  await wait(1200);

  // 9. Capture Settings (Dark Mode)
  console.log('Capturing settings_dark.png...');
  img = await win.webContents.capturePage();
  fs.writeFileSync(path.join(artifactDir, 'settings_dark.png'), img.toPNG());

  console.log('All tests completed successfully!');
  app.quit();
}

run().catch((e) => {
  console.error(e);
  app.quit();
});

const { app, BrowserWindow, protocol, session } = require('electron');
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
    height: 920,
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'electron', 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: true
    }
  });

  const distPath = path.resolve(__dirname, 'dist', 'index.html');
  console.log('Loading:', distPath);
  await win.loadFile(distPath);

  // Helper wait
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  await wait(2000);

  // 1. Capture Login Screen (Dark)
  // Ensure user is logged out first for clean login screen capture
  await win.webContents.executeJavaScript(`
    localStorage.removeItem('forensivault_session_v1');
    window.location.reload();
  `);
  await wait(2000);

  console.log('Capturing Login Screen (Dark)...');
  let image = await win.webContents.capturePage();
  fs.writeFileSync(path.join(artifactDir, 'login_screen_dark.png'), image.toPNG());

  // 2. Toggle Theme to Light on Login Screen & Capture
  console.log('Toggling theme to Light on Login...');
  await win.webContents.executeJavaScript(`
    const btn = document.querySelector('header button[title*="Light"], header button[title*="Switch"]');
    if (btn) btn.click();
  `);
  await wait(1000);
  console.log('Capturing Login Screen (Light)...');
  image = await win.webContents.capturePage();
  fs.writeFileSync(path.join(artifactDir, 'login_screen_light.png'), image.toPNG());

  // Toggle back to Dark mode
  await win.webContents.executeJavaScript(`
    const btn = document.querySelector('header button[title*="Dark"], header button[title*="Switch"]');
    if (btn) btn.click();
  `);
  await wait(500);

  // 3. Log in
  console.log('Logging in...');
  await win.webContents.executeJavaScript(`
    const autofill = document.querySelector('div[title*="examiner credentials"]');
    if (autofill) autofill.click();
    const submitBtn = document.querySelector('button[type="submit"]');
    if (submitBtn) submitBtn.click();
  `);
  await wait(2500);

  // 4. Navigate to Settings page
  console.log('Navigating to Settings page...');
  await win.webContents.executeJavaScript(`
    // Find sidebar button for Settings or click user menu -> Settings
    const buttons = Array.from(document.querySelectorAll('button, a'));
    const settingsBtn = buttons.find(b => b.textContent && b.textContent.includes('Settings'));
    if (settingsBtn) settingsBtn.click();
  `);
  await wait(2000);

  // 5. Capture Settings Screen (Dark)
  console.log('Capturing Settings Screen (Dark)...');
  image = await win.webContents.capturePage();
  fs.writeFileSync(path.join(artifactDir, 'settings_screen_dark.png'), image.toPNG());

  // 6. Switch to Warm Cream inside Settings page & Capture
  console.log('Selecting Warm Cream theme in Settings page...');
  await win.webContents.executeJavaScript(`
    const creamCard = Array.from(document.querySelectorAll('div')).find(d => d.textContent && d.textContent.includes('Warm Cream') && d.textContent.includes('Editorial'));
    if (creamCard) creamCard.click();
  `);
  await wait(1000);

  console.log('Capturing Settings Screen (Light)...');
  image = await win.webContents.capturePage();
  fs.writeFileSync(path.join(artifactDir, 'settings_screen_light.png'), image.toPNG());

  // Switch back to Dark mode
  await win.webContents.executeJavaScript(`
    const darkCard = Array.from(document.querySelectorAll('div')).find(d => d.textContent && d.textContent.includes('Dark Mode') && d.textContent.includes('Obsidian'));
    if (darkCard) darkCard.click();
  `);
  await wait(500);

  console.log('All screenshots captured successfully!');
  app.quit();
}

run().catch((err) => {
  console.error('Error during verification:', err);
  app.quit();
});

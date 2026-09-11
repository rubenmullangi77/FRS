const { app, BrowserWindow } = require('electron');
const path = require('path');

app.whenReady().then(async () => {
  const win = new BrowserWindow({ show: false });
  await win.loadFile(path.resolve(__dirname, 'dist', 'index.html'));
  
  const res = await win.webContents.executeJavaScript(`(() => {
    const root = document.documentElement;
    root.classList.remove('dark');
    root.setAttribute('data-theme', 'light');
    return {
      bodyBg: window.getComputedStyle(document.body).backgroundColor,
      htmlBg: window.getComputedStyle(root).backgroundColor,
      varBgMain: window.getComputedStyle(root).getPropertyValue('--bg-main')
    };
  })()`);
  
  console.log('LIGHT MODE BODY BG:', JSON.stringify(res));
  app.quit();
});

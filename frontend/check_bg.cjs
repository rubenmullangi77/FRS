const { app, BrowserWindow } = require('electron');
const path = require('path');

app.whenReady().then(async () => {
  const win = new BrowserWindow({ show: false, width: 1440, height: 900 });
  await win.loadFile(path.resolve(__dirname, 'dist', 'index.html'));
  await new Promise(r => setTimeout(r, 1000));

  const report = await win.webContents.executeJavaScript(`(() => {
    const btn = document.getElementById('login-theme-toggle');
    if (btn) btn.click();
    
    const root = document.documentElement;
    const body = document.body;
    const container = document.querySelector('div.min-h-screen');
    const header = document.querySelector('header');
    
    return {
      htmlBg: window.getComputedStyle(root).backgroundColor,
      bodyBg: window.getComputedStyle(body).backgroundColor,
      containerBg: container ? window.getComputedStyle(container).backgroundColor : null,
      headerBg: header ? window.getComputedStyle(header).backgroundColor : null,
      varBgMain: window.getComputedStyle(root).getPropertyValue('--bg-main'),
      varSurface: window.getComputedStyle(root).getPropertyValue('--surface'),
      classes: root.className,
      dataTheme: root.getAttribute('data-theme')
    };
  })()`);

  console.log('THEME REPORT:', JSON.stringify(report, null, 2));
  app.quit();
});

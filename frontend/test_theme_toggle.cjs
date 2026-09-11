const { app, BrowserWindow } = require('electron');
const path = require('path');

app.whenReady().then(async () => {
  const win = new BrowserWindow({ show: false, width: 1440, height: 900 });
  await win.loadFile(path.resolve(__dirname, 'dist', 'index.html'));
  await new Promise((r) => setTimeout(r, 1000));

  const info1 = await win.webContents.executeJavaScript(`(() => {
    return {
      classes: document.documentElement.className,
      dataTheme: document.documentElement.getAttribute('data-theme'),
      bgMain: window.getComputedStyle(document.documentElement).getPropertyValue('--bg-main'),
      bodyBg: window.getComputedStyle(document.body).backgroundColor
    };
  })()`);
  console.log('INITIAL (Dark):', JSON.stringify(info1));

  const info2 = await win.webContents.executeJavaScript(`(() => {
    const btn = document.getElementById('login-theme-toggle');
    if (btn) btn.click();
    return {
      classes: document.documentElement.className,
      dataTheme: document.documentElement.getAttribute('data-theme'),
      bgMain: window.getComputedStyle(document.documentElement).getPropertyValue('--bg-main'),
      bodyBg: window.getComputedStyle(document.body).backgroundColor
    };
  })()`);
  console.log('AFTER TOGGLE:', JSON.stringify(info2));

  app.quit();
});

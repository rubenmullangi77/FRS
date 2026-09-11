const { app, BrowserWindow } = require('electron');
const path = require('path');

app.whenReady().then(async () => {
  const win = new BrowserWindow({ show: false, width: 1440, height: 900 });
  await win.loadFile(path.resolve(__dirname, 'dist', 'index.html'));
  await new Promise((r) => setTimeout(r, 1000));

  const debug = await win.webContents.executeJavaScript(`(() => {
    const btn = document.getElementById('login-theme-toggle');
    const logs = [];
    logs.push({ btnExists: !!btn, btnHtml: btn ? btn.outerHTML : null });
    
    // Check localStorage
    logs.push({ localTheme: localStorage.getItem('forensivault_theme_mode') });
    
    // Simulate click
    if (btn) {
      btn.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
    }
    
    logs.push({
      afterClickLocalTheme: localStorage.getItem('forensivault_theme_mode'),
      classes: document.documentElement.className,
      dataTheme: document.documentElement.getAttribute('data-theme')
    });
    
    return logs;
  })()`);
  console.log('DEBUG LOGS:', JSON.stringify(debug, null, 2));

  app.quit();
});

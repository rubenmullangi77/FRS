const { app, BrowserWindow } = require('electron');
const path = require('path');

app.whenReady().then(async () => {
  const win = new BrowserWindow({ show: false, width: 1440, height: 900 });
  await win.loadFile(path.resolve(__dirname, 'dist', 'index.html'));
  await new Promise(r => setTimeout(r, 1000));
  await win.webContents.executeJavaScript(`
    localStorage.setItem('forensivault_auth_session_v1', JSON.stringify({
      isAuthenticated: true,
      user: { username: 'Ruben', role: 'Lead Forensic Examiner' },
      token: 'mock-token'
    }));
    window.location.reload();
  `);
  await new Promise(r => setTimeout(r, 1500));
  await win.webContents.executeJavaScript(`
    const btn = Array.from(document.querySelectorAll('button')).find(b => b.textContent && b.textContent.includes('Settings'));
    if (btn) btn.click();
  `);
  await new Promise(r => setTimeout(r, 1000));
  const res = await win.webContents.executeJavaScript(`
    const cards = document.querySelectorAll('.workstation-card');
    Array.from(cards).map(c => {
      const s = window.getComputedStyle(c);
      return {
        classes: c.className,
        padding: s.padding,
        paddingTop: s.paddingTop,
        bg: s.backgroundColor,
        border: s.border,
        rect: c.getBoundingClientRect()
      };
    });
  `);
  console.log('CARDS_STYLE_RESULT:' + JSON.stringify(res, null, 2));
  app.quit();
});

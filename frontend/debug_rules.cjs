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
    const card = document.querySelector('.workstation-card');
    const matched = [];
    for (const sheet of document.styleSheets) {
      try {
        for (const rule of sheet.cssRules) {
          if (rule.selectorText && card.matches(rule.selectorText)) {
            matched.push({ selector: rule.selectorText, css: rule.cssText });
          }
        }
      } catch (e) {}
    }
    ({
      matched,
      computedPadding: window.getComputedStyle(card).padding,
      computedPaddingTop: window.getComputedStyle(card).paddingTop
    });
  `);
  console.log('RULES_RESULT:' + JSON.stringify(res, null, 2));
  app.quit();
});

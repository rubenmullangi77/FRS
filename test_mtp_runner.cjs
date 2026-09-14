const { app, BrowserWindow } = require('electron');const path = require('path');
const fs = require('fs');

const projectRoot = path.resolve(__dirname);
const distPath = path.join(projectRoot, 'frontend', 'dist', 'index.html');


app.whenReady().then(async () => {
  const win = new BrowserWindow({
    width: 1440,
    height: 960,
    backgroundColor: '#FFF8EE',
    show: true,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      webSecurity: false
    }
  });

  win.webContents.on('console-message', (ev, l, msg) => {
    console.log('[Renderer] ' + msg);
  });

  console.log('[Test Runner] Loading UI from:', distPath);
  await win.loadFile(distPath);

  const exec = (c) => win.webContents.executeJavaScript(c);
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const snap = async (name) => {
    await exec("(function() { const m = document.querySelector('main'); if (m) m.scrollTop = 750; })();");
    await sleep(400);
    const img = await win.webContents.capturePage();
    const out = path.join(projectRoot, name);
    fs.writeFileSync(out, img.toPNG());
    console.log('[Screenshot Saved] -> ' + out);
  };

  try {
    console.log('[Step 1] Waiting for Login Page...');
    await sleep(2000);

    console.log('[Step 2] Performing Examiner Login...');
    await exec (`(function() {
      const btns = Array.from(document.querySelectorAll('button'));
      const autofill = btns.find(b => b.textContent.includes('Autofill'));
      if (autofill) autofill.click();
      setTimeout(() => {
        const auth = btns.find(b => b.textContent.includes('Authenticate') || b.textContent.includes('Sign In'));
        if (auth) auth.click();
      }, 400);
    })();`);
    await sleep(2500);

    console.log('[Step 3] Navigating to Recovery Page...');
    await exec(`(function() {
      const btn = document.getElementById('nav-recovery');
      if (btn) btn.click();
    })();`);
    await sleep(2500);
    await snap('screenshot_01_recovery_sources.png');

    console.log('[Step 4] Selecting Portable Device (iQOO 7)...');
    await exec(`(function() {
      const tabBtn = Array.from(document.querySelectorAll('button')).find(b => b.textContent && b.textContent.includes('Portable Devices'));
      if (tabBtn) tabBtn.click();
    })();`);
    await sleep(1200);
    await exec(`(function() {
      const cards = Array.from(document.querySelectorAll('div, button, [role="button"]'));
      const phone = cards.find(c => c.textContent && c.textContent.includes('iQOO 7'));
      if (phone) phone.click();
    })();`);
    await sleep(4000);
    await snap('screenshot_02_mtp_internal_storage.png');


    console.log('[Step 4B] Opening Internal storage (s10001)...');
    await exec(`(function() {
      const rows = Array.from(document.querySelectorAll('tr'));
      const isRow = rows.find(r => r.textContent && r.textContent.includes('Internal storage'));
      if (isRow) {
        const btn = isRow.querySelector('button') || isRow;
        btn.click();
      }
    })();`);
    await sleep(3500);
    await snap('screenshot_02b_inside_internal_storage.png');

    console.log('[Step 5] Clicking Download folder (o9)...');
    await exec(`(function() {
      const rows = Array.from(document.querySelectorAll('tr'));
      const dl = rows.find(r => r.textContent && r.textContent.includes('Download') && !r.textContent.includes('vivo'));
      if (dl) {
        const btn = dl.querySelector('button') || dl;
        btn.click();
      }
    })();`);
    await sleep(3000);
    await snap('screenshot_03_mtp_downloads_empty.png');

    console.log('[Step 6] Clicking Back button...');
    await exec(`(function() {
      const btns = Array.from(document.querySelectorAll('button'));
      const back = btns.find(b => b.textContent.includes('Back'));
      if (back) back.click();
    })();`);
    await sleep(3000);

    console.log('[Step 7] Navigating into Pictures -> vivogallery -> trash...');
    await exec(`(function() {
      const rows = Array.from(document.querySelectorAll('tr'));
      const pic = rows.find(r => r.textContent && r.textContent.includes('Pictures'));
      if (pic) {
        const btn = pic.querySelector('button') || pic;
        btn.click();
      }
    })();`);
    await sleep(3000);

    await exec(`(function() {
      const rows = Array.from(document.querySelectorAll('tr'));
      const vg = rows.find(r => r.textContent && r.textContent.includes('vivogallery'));
      if (vg) {
        const btn = vg.querySelector('button') || vg;
        btn.click();
      }
    })();`);
    await sleep(3000);

    await exec(`(function() {
      const rows = Array.from(document.querySelectorAll('tr'));
      const tr = rows.find(r => r.textContent && r.textContent.includes('trash'));
      if (tr) {
        const btn = tr.querySelector('button') || tr;
        btn.click();
      }
    })();`);
    await sleep(4000);
    await snap('screenshot_04_mtp_trash_files.png');

    console.log('[Step 8] Clicking Delete on a trashed file...');
    await exec(`(function() {
      const btns = Array.from(document.querySelectorAll('button')).filter(b => b.textContent.trim() === 'Delete');
      if (btns.length > 0) btns[0].click();
    })();`);
    await sleep(2000);
    await snap('screenshot_05_mtp_delete_modal.png');

    console.log('[Step 9] Confirming deletion modal...');
    await exec(`(function() {
      const inputs = Array.from(document.querySelectorAll('input'));
      const confirmInput = inputs.find(i => i.placeholder && i.placeholder.includes('DELETE'));
      if (confirmInput) {
        confirmInput.value = 'DELETE';
        confirmInput.dispatchEvent(new Event('input', { bubbles: true }));
      }
      const pwInput = inputs.find(i => i.type === 'password');
      if (pwInput) {
        pwInput.value = 'rube';
        pwInput.dispatchEvent(new Event('input', { bubbles: true }));
      }
    })();`);
    await sleep(800);
    await snap('screenshot_06_mtp_delete_modal_filled.png');

    console.log('[Step 10] Submitting deletion...');
    await exec(`(function() {
      const btns = Array.from(document.querySelectorAll('button'));
      const submitBtn = btns.find(b => b.textContent.includes('Delete File from Device') || b.textContent.includes('Permanently Delete Object'));
      if (submitBtn) submitBtn.click();
    })();`);
    await sleep(5000);
    await snap('screenshot_07_mtp_deletion_result.png');

    console.log('[End-to-End Test Passed]');
  } catch (err) {
    console.error('[Test Error]', err);
  } finally {
    setTimeout(() => app.quit(), 1000);
  }
});

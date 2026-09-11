const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('forensiVaultDesktop', {
  platform: process.platform,
  version: '1.0.0',
  isDesktop: true,
  ping: () => ipcRenderer.invoke('desktop:ping')
});

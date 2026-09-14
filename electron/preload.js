const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('forensiVaultDesktop', {
  platform: process.platform,
  version: '1.0.0',
  isDesktop: true,
  ping: () => ipcRenderer.invoke('desktop:ping'),
  openPath: (targetPath) => ipcRenderer.invoke('desktop:openPath', targetPath),
  openReportPdf: (targetPath) => ipcRenderer.invoke('desktop:openReportPdf', targetPath),
  openRecoveryFolder: (targetPath) => ipcRenderer.invoke('desktop:openRecoveryFolder', targetPath)
});

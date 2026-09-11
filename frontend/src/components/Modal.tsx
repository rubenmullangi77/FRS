import React, { useEffect } from 'react';
import { X, AlertTriangle, ShieldAlert } from 'lucide-react';

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
  variant?: 'default' | 'danger' | 'warning' | 'info';
  confirmText?: string;
  cancelText?: string;
  onConfirm?: () => void;
  isConfirmDisabled?: boolean;
  isLoading?: boolean;
}

export const Modal: React.FC<ModalProps> = ({
  isOpen,
  onClose,
  title,
  children,
  variant = 'default',
  confirmText,
  cancelText = 'Cancel',
  onConfirm,
  isConfirmDisabled = false,
  isLoading = false
}) => {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const headerColors = {
    default: 'text-[#2B241F] border-[#E5D8C8]',
    danger: 'text-[#C53030] border-[#C53030]/30 bg-[#C53030]/5',
    warning: 'text-[#B45309] border-[#B45309]/30 bg-[#B45309]/5',
    info: 'text-[#D96B27] border-[#D96B27]/30 bg-[#F4D5BF]/20'
  };

  const confirmBtnStyles = {
    default: 'bg-[#D96B27] hover:bg-[#B9541D] text-white',
    danger: 'bg-[#C53030] hover:bg-[#9B2C2C] text-white shadow-xs',
    warning: 'bg-[#B45309] hover:bg-[#92400E] text-white font-bold',
    info: 'bg-[#D96B27] hover:bg-[#B9541D] text-white'
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-xs animate-fade-in">
      <div className="bg-[#FFFDF8] border border-[#E5D8C8] rounded-xl w-full max-w-2xl shadow-xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className={`px-6 py-4 border-b flex items-center justify-between ${headerColors[variant]}`}>
          <div className="flex items-center gap-2 font-bold text-base">
            {variant === 'danger' && <ShieldAlert size={20} className="text-[#C53030]" />}
            {variant === 'warning' && <AlertTriangle size={20} className="text-[#B45309]" />}
            <span>{title}</span>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-md text-[#756B63] hover:text-[#2B241F] hover:bg-[#FBF8F1] transition-colors cursor-pointer"
          >
            <X size={18} />
          </button>
        </div>

        {/* Modal Body */}
        <div className="px-6 py-5 overflow-y-auto space-y-4 text-sm text-[#2B241F]">
          {children}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-4 border-t border-[#E5D8C8] bg-[#FBF8F1] flex items-center justify-end gap-3">
          <button
            type="button"
            onClick={onClose}
            disabled={isLoading}
            className="px-4 py-2 rounded-lg text-xs font-bold text-[#756B63] hover:text-[#2B241F] hover:bg-[#E5D8C8]/40 border border-[#E5D8C8] transition-colors disabled:opacity-50 cursor-pointer"
          >
            {cancelText}
          </button>
          {confirmText && onConfirm && (
            <button
              type="button"
              onClick={onConfirm}
              disabled={isConfirmDisabled || isLoading}
              className={`px-5 py-2 rounded-lg text-xs font-bold transition-colors disabled:opacity-50 flex items-center gap-2 cursor-pointer shadow-xs ${confirmBtnStyles[variant]}`}
            >
              {isLoading && (
                <div className="w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full animate-spin" />
              )}
              <span>{confirmText}</span>
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

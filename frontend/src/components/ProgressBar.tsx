import React from 'react';

interface ProgressBarProps {
  progress: number; // 0 - 100
  stage?: string;
  color?: 'emerald' | 'cyan' | 'amber' | 'rose' | 'purple' | 'orange';
  height?: 'sm' | 'md' | 'lg';
  showPercentage?: boolean;
}

export const ProgressBar: React.FC<ProgressBarProps> = ({
  progress,
  stage,
  color = 'orange',
  height = 'md',
  showPercentage = true
}) => {
  const clampedProgress = Math.min(100, Math.max(0, Math.round(progress)));

  const heightClasses = {
    sm: 'h-1.5',
    md: 'h-2.5',
    lg: 'h-3.5'
  };

  const barColors = {
    orange: 'bg-[#D96B27]',
    emerald: 'bg-[#2E7D32]',
    cyan: 'bg-[#D96B27]',
    amber: 'bg-[#B45309]',
    rose: 'bg-[#C53030]',
    purple: 'bg-[#D96B27]'
  };

  return (
    <div className="w-full space-y-1.5">
      {(stage || showPercentage) && (
        <div className="flex items-center justify-between text-xs font-mono text-[#756B63]">
          <span className="truncate max-w-[80%] text-[#2B241F] font-bold">{stage}</span>
          {showPercentage && (
            <span className="font-bold text-[#D96B27]">{clampedProgress}%</span>
          )}
        </div>
      )}
      <div className={`w-full bg-[#E5D8C8]/60 rounded-full overflow-hidden ${heightClasses[height]} border border-[#E5D8C8]`}>
        <div
          className={`h-full transition-all duration-300 rounded-full ${barColors[color]}`}
          style={{ width: `${clampedProgress}%` }}
        />
      </div>
    </div>
  );
};

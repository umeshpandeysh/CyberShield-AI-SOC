import React from 'react';

export const TableSkeleton: React.FC<{ rows?: number }> = ({ rows = 5 }) => {
  return (
    <div className="space-y-3 p-4">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="h-10 w-full skeleton rounded-xl" />
      ))}
    </div>
  );
};

export const CardSkeleton: React.FC = () => {
  return <div className="h-28 w-full skeleton rounded-xl" />;
};

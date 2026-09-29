import React from 'react';
import './BottomControls.css';

const BottomControls = ({ isPaused, onPauseToggle, onResetView }) => {
  return (
    <div className="bottom-bar-panel">
      <button className={`bottom-ctrl-btn ${isPaused ? 'paused' : ''}`} onClick={onPauseToggle}>
        {isPaused ? 'Resume' : 'Pause'}
      </button>
      <button className="bottom-ctrl-btn" onClick={onResetView}>
        Reset View
      </button>
    </div>
  );
};

export default BottomControls;

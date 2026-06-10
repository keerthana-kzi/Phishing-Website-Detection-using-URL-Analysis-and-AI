// Content Script - Page Behavior Monitor

(function() {
  'use strict';
  
  console.log('🔍 Phishing Detector - Content Script Active');
  
  const behaviorData = {
    formCount: 0,
    passwordFields: 0,
    hiddenInputs: 0,
    iframes: 0,
    externalLinks: 0,
    suspiciousPatterns: [],
    popups: 0
  };
  
  // ENHANCED SUSPICIOUS PATTERNS
  const SUSPICIOUS_PATTERNS = [
    'verify your account', 'account suspended', 'urgent action required',
    'confirm your identity', 'update payment information', 'unusual activity',
    'security alert', 'account will be closed', 'claim your prize',
    'you have won', 'click here immediately', 'limited time offer',
    'account locked', 'verify identity', 'confirm payment', 'update billing',
    'unusual sign-in', 'suspicious activity', 'verify now', 'action required',
    'immediate action', 'security check', 'confirm account', 'restore access'
  ];
  
  let userWarned = false;
  
  // Initialize
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
  
  function init() {
    console.log('🚀 Initializing behavior analysis');
    analyzePage();
    setupMonitoring();
    sendBehaviorData();
    
    // Check risk after delay
    setTimeout(checkAndWarn, 2500);
  }
  
  function analyzePage() {
    // Count forms
    behaviorData.formCount = document.querySelectorAll('form').length;
    
    // Count password fields
    behaviorData.passwordFields = document.querySelectorAll('input[type="password"]').length;
    
    // Count hidden inputs
    behaviorData.hiddenInputs = document.querySelectorAll('input[type="hidden"]').length;
    
    // Count iframes
    behaviorData.iframes = document.querySelectorAll('iframe').length;
    
    // Count external links
    const currentDomain = window.location.hostname;
    const links = document.querySelectorAll('a[href]');
    behaviorData.externalLinks = Array.from(links).filter(link => {
      try {
        const url = new URL(link.href);
        return url.hostname !== currentDomain;
      } catch {
        return false;
      }
    }).length;
    
    // Detect suspicious patterns
    const pageText = document.body.innerText.toLowerCase();
    SUSPICIOUS_PATTERNS.forEach(pattern => {
      if (pageText.includes(pattern)) {
        if (!behaviorData.suspiciousPatterns.includes(pattern)) {
          behaviorData.suspiciousPatterns.push(pattern);
        }
      }
    });
    
    // Check suspicious forms
    checkSuspiciousForms();
    
    console.log('📊 Behavior data:', behaviorData);
  }
  
  function checkSuspiciousForms() {
    const forms = document.querySelectorAll('form');
    
    forms.forEach(form => {
      const action = form.getAttribute('action');
      const hasPassword = form.querySelector('input[type="password"]');
      
      // Suspicious: Password form with no action or javascript action
      if (hasPassword && (!action || action === '' || action.startsWith('javascript:'))) {
        behaviorData.suspiciousPatterns.push('Password form with suspicious action');
      }
      
      // Suspicious: Form posts to external domain
      if (action && hasPassword) {
        try {
          const actionUrl = new URL(action, window.location.href);
          if (actionUrl.hostname !== window.location.hostname) {
            behaviorData.suspiciousPatterns.push('Password form posts to external domain');
          }
        } catch (e) {}
      }
      
      // Check for credit card fields
      const inputs = form.querySelectorAll('input');
      const inputNames = Array.from(inputs).map(i => 
        (i.name || i.id || i.placeholder || '').toLowerCase()
      );
      
      if (inputNames.some(name => name.includes('card') || name.includes('cvv'))) {
        behaviorData.suspiciousPatterns.push('Form requests credit card');
      }
      
      if (inputNames.some(name => name.includes('ssn') || (name.includes('social') && name.includes('security')))) {
        behaviorData.suspiciousPatterns.push('Form requests SSN');
      }
    });
  }
  
  function setupMonitoring() {
    // Monitor popups
    const originalOpen = window.open;
    window.open = function(...args) {
      behaviorData.popups++;
      console.log('🚨 Popup detected');
      sendBehaviorData();
      return originalOpen.apply(this, args);
    };
    
    // Monitor form submissions
    document.addEventListener('submit', (e) => {
      const form = e.target;
      const action = form.getAttribute('action');
      
      if (!action || action.includes('javascript:')) {
        console.log('⚠️ Suspicious form submission');
        behaviorData.suspiciousPatterns.push('Suspicious form submission');
        sendBehaviorData();
      }
    }, true);
    
    // Monitor password fields
    const passwordFields = document.querySelectorAll('input[type="password"]');
    passwordFields.forEach(field => {
      field.addEventListener('focus', handlePasswordFocus);
      field.addEventListener('input', handlePasswordInput);
    });
    
    // Monitor for new elements
    const observer = new MutationObserver((mutations) => {
      let needsUpdate = false;
      
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === 1) {
            // New password fields
            const newPasswords = node.querySelectorAll ? node.querySelectorAll('input[type="password"]') : [];
            if (newPasswords.length > 0) {
              behaviorData.passwordFields += newPasswords.length;
              newPasswords.forEach(field => {
                field.addEventListener('focus', handlePasswordFocus);
                field.addEventListener('input', handlePasswordInput);
              });
              needsUpdate = true;
            }
            
            // New iframes
            const newIframes = node.querySelectorAll ? node.querySelectorAll('iframe') : [];
            if (newIframes.length > 0) {
              behaviorData.iframes += newIframes.length;
              needsUpdate = true;
            }
          }
        });
      });
      
      if (needsUpdate) {
        sendBehaviorData();
      }
    });
    
    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }
  
  function handlePasswordFocus() {
    checkAndWarn();
  }
  
  function handlePasswordInput(e) {
    if (e.target.value.length >= 3 && !userWarned) {
      checkAndWarn();
    }
  }
  
  async function checkAndWarn() {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tabs || tabs.length === 0) return;
      
      const result = await chrome.storage.local.get(`analysis_${tabs[0].id}`);
      const analysis = result[`analysis_${tabs[0].id}`];
      
      if (analysis && (analysis.riskLevel === 'high' || analysis.riskLevel === 'medium') && !userWarned) {
        userWarned = true;
        showWarningBanner(analysis.riskLevel, analysis.overallScore);
      }
    } catch (error) {
      console.log('Could not check risk:', error);
    }
  }
  
  function showWarningBanner(risk, score) {
    const existing = document.getElementById('phishing-detector-warning');
    if (existing) existing.remove();
    
    const isHigh = risk === 'high';
    const bgColor = isHigh ? '#dc2626' : '#f59e0b';
    const title = isHigh ? '🚨 PHISHING ALERT!' : '⚠️ SUSPICIOUS WEBSITE';
    const message = isHigh 
      ? `This site is LIKELY PHISHING (${score}/100 risk). DO NOT enter passwords!`
      : `This site shows suspicious signs (${score}/100 risk). Verify URL before entering data.`;
    
    const banner = document.createElement('div');
    banner.id = 'phishing-detector-warning';
    banner.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      background: ${bgColor};
      color: white;
      padding: 16px 20px;
      z-index: 2147483647;
      box-shadow: 0 4px 12px rgba(0,0,0,0.4);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 15px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      animation: slideDown 0.4s ease-out;
    `;
    
    banner.innerHTML = `
      <style>
        @keyframes slideDown {
          from { transform: translateY(-100%); }
          to { transform: translateY(0); }
        }
      </style>
      <div style="display: flex; align-items: center; gap: 14px;">
        <span style="font-size: 28px;">${isHigh ? '🚨' : '⚠️'}</span>
        <div>
          <strong style="font-size: 17px; font-weight: 700;">${title}</strong><br>
          <span style="font-size: 14px;">${message}</span>
        </div>
      </div>
      <button id="dismiss-warning" style="
        background: rgba(255,255,255,0.2);
        border: 2px solid white;
        color: white;
        padding: 10px 18px;
        border-radius: 6px;
        cursor: pointer;
        font-weight: 700;
      ">Dismiss</button>
    `;
    
    document.body.insertBefore(banner, document.body.firstChild);
    
    document.getElementById('dismiss-warning').addEventListener('click', () => {
      banner.remove();
    });
    
    // Auto-dismiss after 20 seconds
    setTimeout(() => banner.remove(), 20000);
  }
  
  function sendBehaviorData() {
    chrome.runtime.sendMessage({
      type: 'behaviorData',
      data: behaviorData
    }).catch(() => {});
  }
  
  // Send initial data
  setTimeout(sendBehaviorData, 1500);
  
  // Periodic updates
  setInterval(sendBehaviorData, 3000);
  
})();
// Behavior Analysis Module
export async function analyzeBehavior(tabId) {
  try {
    // Retrieve behavior data from storage
    const result = await chrome.storage.local.get(`behavior_${tabId}`);
    const behaviorData = result[`behavior_${tabId}`] || getDefaultBehaviorData();
    
    const score = calculateBehaviorScore(behaviorData);
    const flags = identifyBehaviorFlags(behaviorData);
    
    return {
      score,
      data: behaviorData,
      flags
    };
  } catch (error) {
    console.error('Behavior analysis error:', error);
    return {
      score: 0,
      data: getDefaultBehaviorData(),
      flags: []
    };
  }
}

function getDefaultBehaviorData() {
  return {
    formCount: 0,
    inputFields: [],
    externalLinks: 0,
    suspiciousPatterns: [],
    iframes: 0,
    popups: 0,
    redirects: 0,
    hiddenElements: 0
  };
}

function calculateBehaviorScore(data) {
  let riskScore = 0;
  
  // Form analysis
  if (data.formCount > 3) riskScore += 10;
  
  // Check for password fields without proper security
  const passwordFields = data.inputFields.filter(f => f.type === 'password');
  if (passwordFields.length > 0) {
    const hiddenPasswordFields = passwordFields.filter(f => f.isHidden);
    if (hiddenPasswordFields.length > 0) riskScore += 25;
    
    const noAutocomplete = passwordFields.filter(f => !f.hasAutocomplete);
    if (noAutocomplete.length > 0) riskScore += 10;
  }
  
  // External links
  if (data.externalLinks > 10) riskScore += 15;
  if (data.externalLinks > 20) riskScore += 10;
  
  // Suspicious patterns
  riskScore += Math.min(data.suspiciousPatterns.length * 10, 40);
  
  // Iframes (often used in phishing)
  if (data.iframes > 0) riskScore += 15;
  if (data.iframes > 2) riskScore += 10;
  
  // Popups
  if (data.popups > 0) riskScore += 20;
  if (data.popups > 2) riskScore += 15;
  
  // Redirects
  if (data.redirects > 1) riskScore += 15;
  if (data.redirects > 3) riskScore += 15;
  
  // Hidden elements
  if (data.hiddenElements > 5) riskScore += 10;
  if (data.hiddenElements > 10) riskScore += 10;
  
  return Math.min(riskScore, 100);
}

function identifyBehaviorFlags(data) {
  const flags = [];
  
  if (data.formCount > 3) {
    flags.push(`Multiple forms detected (${data.formCount})`);
  }
  
  const passwordFields = data.inputFields.filter(f => f.type === 'password');
  if (passwordFields.length > 0) {
    flags.push(`${passwordFields.length} password field(s) detected`);
  }
  
  const hiddenPasswordFields = passwordFields.filter(f => f.isHidden);
  if (hiddenPasswordFields.length > 0) {
    flags.push('Hidden password fields detected');
  }
  
  if (data.externalLinks > 10) {
    flags.push(`High number of external links (${data.externalLinks})`);
  }
  
  if (data.suspiciousPatterns.length > 0) {
    flags.push(`Suspicious patterns: ${data.suspiciousPatterns.join(', ')}`);
  }
  
  if (data.iframes > 0) {
    flags.push(`Contains ${data.iframes} iframe(s)`);
  }
  
  if (data.popups > 0) {
    flags.push(`${data.popups} popup attempt(s) detected`);
  }
  
  if (data.redirects > 1) {
    flags.push(`Multiple redirects (${data.redirects})`);
  }
  
  if (data.hiddenElements > 5) {
    flags.push(`${data.hiddenElements} hidden form elements`);
  }
  
  return flags;
}
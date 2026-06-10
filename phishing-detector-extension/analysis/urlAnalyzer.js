// URL Analysis Module
export async function analyzeURL(url) {
  try {
    const urlObj = new URL(url);
    const features = extractURLFeatures(urlObj);
    const score = calculateURLScore(features);
    
    return {
      score,
      features,
      flags: identifyFlags(features)
    };
  } catch (error) {
    console.error('URL analysis error:', error);
    return {
      score: 50,
      features: {},
      flags: ['Invalid URL']
    };
  }
}

function extractURLFeatures(urlObj) {
  const hostname = urlObj.hostname;
  const path = urlObj.pathname;
  const fullUrl = urlObj.href;
  
  return {
    // Length features
    urlLength: fullUrl.length,
    hostnameLength: hostname.length,
    pathLength: path.length,
    
    // Domain features
    domainLevels: hostname.split('.').length,
    hasSubdomain: hostname.split('.').length > 2,
    tld: hostname.split('.').pop(),
    
    // Suspicious characters
    hasIPAddress: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(hostname),
    hasAtSymbol: fullUrl.includes('@'),
    dashCount: (hostname.match(/-/g) || []).length,
    dotCount: (hostname.match(/\./g) || []).length,
    underscoreCount: (hostname.match(/_/g) || []).length,
    doubleSlash: (fullUrl.match(/\/\//g) || []).length > 1,
    
    // Protocol
    isHTTPS: urlObj.protocol === 'https:',
    hasPort: urlObj.port !== '',
    
    // Path features
    hasQueryParams: urlObj.search !== '',
    queryParamCount: urlObj.searchParams.size,
    pathDepth: path.split('/').filter(p => p).length,
    
    // Suspicious patterns
    hasSuspiciousKeywords: checkSuspiciousKeywords(fullUrl),
    hasBrandImitation: checkBrandImitation(hostname),
    hasHomograph: checkHomograph(hostname),
    hasHexEncoding: /%[0-9a-f]{2}/i.test(fullUrl),
    
    // Entropy
    hostnameEntropy: calculateEntropy(hostname),
    pathEntropy: calculateEntropy(path)
  };
}

function calculateURLScore(features) {
  let riskScore = 0;
  
  // Length checks
  if (features.urlLength > 75) riskScore += 10;
  if (features.hostnameLength > 30) riskScore += 10;
  
  // Domain checks
  if (features.hasIPAddress) riskScore += 20;
  if (features.domainLevels > 4) riskScore += 15;
  if (features.dashCount > 2) riskScore += 10;
  if (features.dotCount > 4) riskScore += 10;
  
  // Protocol and security
  if (!features.isHTTPS) riskScore += 15;
  if (features.hasPort) riskScore += 5;
  
  // Suspicious patterns
  if (features.hasAtSymbol) riskScore += 20;
  if (features.doubleSlash) riskScore += 10;
  if (features.hasSuspiciousKeywords) riskScore += 25;
  if (features.hasBrandImitation) riskScore += 30;
  if (features.hasHomograph) riskScore += 25;
  if (features.hasHexEncoding) riskScore += 10;
  
  // Entropy checks (high entropy = random chars)
  if (features.hostnameEntropy > 4) riskScore += 15;
  if (features.pathEntropy > 4.5) riskScore += 10;
  
  // TLD checks
  const suspiciousTLDs = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top'];
  if (suspiciousTLDs.includes(features.tld)) riskScore += 15;
  
  return Math.min(riskScore, 100);
}

function identifyFlags(features) {
  const flags = [];
  
  if (features.hasIPAddress) flags.push('IP address in URL');
  if (!features.isHTTPS) flags.push('Not using HTTPS');
  if (features.hasSuspiciousKeywords) flags.push('Suspicious keywords detected');
  if (features.hasBrandImitation) flags.push('Possible brand imitation');
  if (features.hasHomograph) flags.push('Homograph characters detected');
  if (features.dashCount > 3) flags.push('Excessive dashes in domain');
  if (features.urlLength > 100) flags.push('Unusually long URL');
  if (features.hasAtSymbol) flags.push('@ symbol in URL');
  if (features.doubleSlash) flags.push('Multiple // in URL');
  
  return flags;
}

function checkSuspiciousKeywords(url) {
  const keywords = [
    'login', 'signin', 'account', 'verify', 'secure', 'update',
    'banking', 'paypal', 'amazon', 'microsoft', 'apple',
    'confirm', 'suspended', 'locked', 'unusual'
  ];
  
  const lowerUrl = url.toLowerCase();
  return keywords.some(keyword => lowerUrl.includes(keyword));
}

function checkBrandImitation(hostname) {
  const brands = [
    'paypal', 'amazon', 'microsoft', 'apple', 'google',
    'facebook', 'netflix', 'instagram', 'twitter', 'linkedin'
  ];
  
  const lowerHostname = hostname.toLowerCase();
  
  // Check for brand names with extra characters
  return brands.some(brand => {
    const hasBrand = lowerHostname.includes(brand);
    const isExactDomain = lowerHostname === `${brand}.com` || 
                          lowerHostname === `www.${brand}.com`;
    return hasBrand && !isExactDomain;
  });
}

function checkHomograph(hostname) {
  // Check for non-ASCII characters that look like ASCII
  const homographs = {
    'Ð°': 'a', 'Ðµ': 'e', 'Ð¾': 'o', 'Ñ€': 'p', 'Ñ': 'c',
    'Ñƒ': 'y', 'Ñ…': 'x', 'Î¯': 'i', 'Î¿': 'o', 'Ñ•': 's'
  };
  
  return Object.keys(homographs).some(char => hostname.includes(char));
}

function calculateEntropy(str) {
  const freq = {};
  for (let char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }
  
  const len = str.length;
  let entropy = 0;
  
  for (let char in freq) {
    const p = freq[char] / len;
    entropy -= p * Math.log2(p);
  }
  
  return entropy;
}
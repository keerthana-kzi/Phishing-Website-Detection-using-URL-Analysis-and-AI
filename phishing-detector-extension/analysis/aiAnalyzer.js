

export async function analyzeWithAI(url) {
  try {
   
    
   
    const features = await extractAIFeatures(url);
    const prediction = await runAIModel(features);
    
    return {
      score: prediction.score,
      confidence: prediction.confidence,
      features,
      reasoning: prediction.reasoning
    };
  } catch (error) {
    console.error('AI analysis error:', error);
    return {
      score: 50,
      confidence: 0,
      features: {},
      reasoning: 'Analysis unavailable'
    };
  }
}

async function extractAIFeatures(url) {
  const urlObj = new URL(url);
  
  return {
    // Lexical features
    urlLength: url.length,
    domainLength: urlObj.hostname.length,
    pathLength: urlObj.pathname.length,
    
    // Character distribution
    digitRatio: calculateDigitRatio(url),
    letterRatio: calculateLetterRatio(url),
    specialCharRatio: calculateSpecialCharRatio(url),
    
    // Token-based features
    tokenCount: urlObj.hostname.split(/[.-]/).length,
    longestToken: getLongestToken(urlObj.hostname),
    avgTokenLength: getAvgTokenLength(urlObj.hostname),
    
    // Security indicators
    hasSSL: urlObj.protocol === 'https:',
    hasStandardPort: !urlObj.port || urlObj.port === '80' || urlObj.port === '443',
    
    // Domain features
    tldTrust: getTLDTrustScore(urlObj.hostname.split('.').pop()),
    domainReputation: await checkDomainReputation(urlObj.hostname),
    
    // Content-based (simulated)
    contentComplexity: Math.random() * 100,
    visualSimilarity: Math.random() * 100
  };
}

async function runAIModel(features) {
  
  
  let score = 0;
  const reasoning = [];
  
  // URL length analysis
  if (features.urlLength > 75) {
    score += 15;
    reasoning.push('Unusually long URL');
  }
  
  // Character distribution analysis
  if (features.digitRatio > 0.3) {
    score += 10;
    reasoning.push('High digit ratio in URL');
  }
  
  if (features.specialCharRatio > 0.2) {
    score += 10;
    reasoning.push('High special character ratio');
  }
  
  // SSL analysis
  if (!features.hasSSL) {
    score += 20;
    reasoning.push('No SSL/TLS encryption');
  }
  
  // Domain analysis
  if (features.tldTrust < 50) {
    score += 15;
    reasoning.push('Low-trust TLD');
  }
  
  if (features.domainReputation < 30) {
    score += 25;
    reasoning.push('Poor domain reputation');
  }
  
  // Token analysis
  if (features.longestToken > 20) {
    score += 10;
    reasoning.push('Unusually long domain token');
  }
  
  // Calculate confidence based on number of features analyzed
  const confidence = Math.min(
    (reasoning.length / 7) * 100,
    95
  );
  
  return {
    score: Math.min(score, 100),
    confidence: Math.round(confidence),
    reasoning: reasoning.length > 0 ? reasoning : ['No suspicious patterns detected']
  };
}

function calculateDigitRatio(str) {
  const digits = str.match(/\d/g) || [];
  return digits.length / str.length;
}

function calculateLetterRatio(str) {
  const letters = str.match(/[a-zA-Z]/g) || [];
  return letters.length / str.length;
}

function calculateSpecialCharRatio(str) {
  const special = str.match(/[^a-zA-Z0-9]/g) || [];
  return special.length / str.length;
}

function getLongestToken(domain) {
  const tokens = domain.split(/[.-]/);
  return Math.max(...tokens.map(t => t.length));
}

function getAvgTokenLength(domain) {
  const tokens = domain.split(/[.-]/).filter(t => t.length > 0);
  const totalLength = tokens.reduce((sum, t) => sum + t.length, 0);
  return tokens.length > 0 ? totalLength / tokens.length : 0;
}

function getTLDTrustScore(tld) {
  const trustedTLDs = {
    'com': 90, 'org': 85, 'net': 80, 'edu': 95, 'gov': 95,
    'co': 75, 'io': 70, 'ai': 70, 'dev': 75
  };
  
  const suspiciousTLDs = {
    'tk': 20, 'ml': 20, 'ga': 20, 'cf': 20, 'gq': 20,
    'xyz': 40, 'top': 35, 'work': 30
  };
  
  if (trustedTLDs[tld]) return trustedTLDs[tld];
  if (suspiciousTLDs[tld]) return suspiciousTLDs[tld];
  return 50; // Unknown TLD
}

async function checkDomainReputation(domain) {
  
  
  // Simulate reputation check
  const knownGoodDomains = [
    'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
    'apple.com', 'github.com', 'stackoverflow.com', 'wikipedia.org'
  ];
  
  if (knownGoodDomains.some(d => domain.includes(d))) {
    return 95;
  }
  
  // Simulate random reputation for unknown domains
  return Math.floor(Math.random() * 100);
}
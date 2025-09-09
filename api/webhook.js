// Vercel Node.js API Route for WhatsApp Flow with Gemini API
// Place this file at: api/webhook.js

import { createHash, createDecipheriv, createCipheriv, randomBytes } from 'crypto';

// --- CORS Headers ---
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
};

// --- Utility Functions ---
function validateEnvironmentVars() {
  const requiredVars = [
    'PRIVATE_KEY',
    'VERIFY_TOKEN',
    'SUPABASE_URL',
    'SUPABASE_ANON_KEY',
    'GEMINI_API_KEY'
  ];
  const missing = requiredVars.filter((varName) => !process.env[varName]);
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
}

async function importPrivateKey(privateKeyPem) {
  const { webcrypto } = await import('crypto');
  const crypto = webcrypto;
  
  const pemHeader = "-----BEGIN PRIVATE KEY-----";
  const pemFooter = "-----END PRIVATE KEY-----";
  const pemContents = privateKeyPem.replace(pemHeader, "").replace(pemFooter, "").replace(/\s/g, "");
  const binaryDer = Uint8Array.from(Buffer.from(pemContents, 'base64'));
  
  return await crypto.subtle.importKey("pkcs8", binaryDer, {
    name: "RSA-OAEP",
    hash: "SHA-256"
  }, false, ["decrypt"]);
}

// --- Encryption/Decryption Functions ---
async function decryptRequest(body, privateKey) {
  const { webcrypto } = await import('crypto');
  const crypto = webcrypto;
  
  const { encrypted_aes_key, encrypted_flow_data, initial_vector } = body;
  if (!encrypted_aes_key || !encrypted_flow_data || !initial_vector) {
    throw new Error('Missing encrypted data fields in the request body');
  }

  try {
    const encryptedAesKeyBuffer = Buffer.from(encrypted_aes_key, 'base64');
    const aesKeyBuffer = new Uint8Array(await crypto.subtle.decrypt({
      name: "RSA-OAEP"
    }, privateKey, encryptedAesKeyBuffer));

    const flowDataBuffer = Buffer.from(encrypted_flow_data, 'base64');
    const initialVectorBuffer = Buffer.from(initial_vector, 'base64');

    const aesKey = await crypto.subtle.importKey("raw", aesKeyBuffer, {
      name: "AES-GCM"
    }, false, ["decrypt"]);

    const decryptedBuffer = await crypto.subtle.decrypt({
      name: "AES-GCM",
      iv: initialVectorBuffer,
      tagLength: 128
    }, aesKey, flowDataBuffer);

    const decryptedJSONString = new TextDecoder().decode(decryptedBuffer);
    const decryptedBody = JSON.parse(decryptedJSONString);

    return {
      decryptedBody,
      aesKeyBuffer,
      initialVectorBuffer
    };
  } catch (error) {
    console.error('Decryption failed:', error);
    throw new Error(`Decryption failed: ${error.message}`);
  }
}

async function encryptResponse(response, aesKeyBuffer, initialVectorBuffer) {
  const { webcrypto } = await import('crypto');
  const crypto = webcrypto;
  
  try {
    const flippedIv = new Uint8Array(initialVectorBuffer.map((byte) => ~byte & 0xFF));

    const aesKey = await crypto.subtle.importKey("raw", aesKeyBuffer, {
      name: "AES-GCM"
    }, false, ["encrypt"]);

    const responseString = JSON.stringify(response);
    const responseBuffer = new TextEncoder().encode(responseString);

    const encryptedBuffer = await crypto.subtle.encrypt({
      name: "AES-GCM",
      iv: flippedIv,
      tagLength: 128
    }, aesKey, responseBuffer);

    // Convert ArrayBuffer to base64 string
    const encryptedUint8Array = new Uint8Array(encryptedBuffer);
    return Buffer.from(encryptedUint8Array).toString('base64');
  } catch (error) {
    console.error('Encryption failed:', error);
    throw new Error(`Encryption failed: ${error.message}`);
  }
}

// Helper function to upload user's reference image to Supabase
async function uploadReferenceImageToSupabase(base64Data) {
  const { createClient } = await import('@supabase/supabase-js');
  const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
  );

  try {
    // Validate input
    if (!base64Data || typeof base64Data !== 'string') {
      throw new Error('Invalid base64 data provided');
    }

    // Clean the base64 data - remove data URL prefix if present
    let cleanBase64 = base64Data;
    if (base64Data.startsWith && base64Data.startsWith('data:')) {
      const base64Index = base64Data.indexOf(',');
      if (base64Index !== -1) {
        cleanBase64 = base64Data.substring(base64Index + 1);
      }
    }

    // Convert base64 to buffer
    const buffer = Buffer.from(cleanBase64, 'base64');
    
    // Generate unique filename for reference image
    const filename = `reference-${Date.now()}.jpg`;
    
    // Upload to reference-photos bucket
    const { data, error } = await supabase.storage
      .from('reference-photos')
      .upload(filename, buffer, {
        contentType: 'image/jpeg',
        upsert: false
      });

    if (error) {
      console.error('Supabase reference upload error:', error);
      throw new Error(`Reference upload failed: ${error.message}`);
    }

    // Get public URL
    const { data: publicUrlData } = supabase.storage
      .from('reference-photos')
      .getPublicUrl(filename);

    console.log('Reference image uploaded:', publicUrlData.publicUrl);
    return publicUrlData.publicUrl;
  } catch (error) {
    console.error('Error uploading reference image to Supabase:', error);
    throw error;
  }
}

// Helper function to upload generated image to Supabase
async function uploadGeneratedImageToSupabase(base64Data, mimeType) {
  const { createClient } = await import('@supabase/supabase-js');
  const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
  );

  try {
    // Convert base64 to buffer
    const buffer = Buffer.from(base64Data, 'base64');
    
    // Generate unique filename for generated image
    const filename = `generated-${Date.now()}.${mimeType.split('/')[1]}`;
    
    // Upload to generated-images bucket
    const { data, error } = await supabase.storage
      .from('generated-images')
      .upload(filename, buffer, {
        contentType: mimeType,
        upsert: false
      });

    if (error) {
      console.error('Supabase generated upload error:', error);
      throw new Error(`Generated upload failed: ${error.message}`);
    }

    // Get public URL
    const { data: publicUrlData } = supabase.storage
      .from('generated-images')
      .getPublicUrl(filename);

    console.log('Generated image uploaded:', publicUrlData.publicUrl);
    return publicUrlData.publicUrl;
  } catch (error) {
    console.error('Error uploading generated image to Supabase:', error);
    throw error;
  }
}

// Helper function to fetch image from URL and convert to base64
async function getImageAsBase64FromUrl(imageUrl) {
  try {
    const response = await fetch(imageUrl);
    if (!response.ok) {
      throw new Error(`Failed to fetch image: ${response.status}`);
    }
    const arrayBuffer = await response.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);
    return buffer.toString('base64');
  } catch (error) {
    console.error('Error fetching image from URL:', error);
    throw error;
  }
}

// Advanced photography specifications for different categories
function getAdvancedPhotographySpecs(category) {
  const baseSpecs = {
    // Fashion & Apparel
    fashion: {
      style: "High-fashion commercial photography with editorial influence",
      shotType: "Full-body lifestyle model shot with dynamic posing",
      composition: "Rule of thirds with leading lines, asymmetrical balance",
      idealBackground: "Textured studio backdrop or sophisticated urban environment",
      studioLighting: "3-point lighting with beauty dish key light",
      cameraSetup: "Medium format camera (Fujifilm GFX100S equivalent)",
      lensChoice: "85mm portrait lens with compression characteristics",
      focalLength: "85-135mm equivalent for flattering perspectives",
      keyLight: "Large softbox at 45° angle with diffusion",
      fillLight: "Reflector or secondary softbox at -2 stops",
      rimLight: "Strip light for edge separation and dimension",
      backgroundLight: "Gradient lighting for visual interest",
      depthOfField: "f/2.8-f/4 for subject isolation with background blur",
      colorGrading: "Fashion-forward color science with skin tone optimization",
      contrastStyle: "Medium contrast with lifted shadows",
      sharpeningApproach: "Selective sharpening on fabric texture and details",
      finishingStyle: "Editorial retouching with natural enhancement",
      aspectRatio: "4:5 portrait for social media optimization",
      visualWeight: "Model-centric with product as hero element",
      marketTier: "Premium to luxury segment",
      targetDemographic: "Fashion-conscious consumers aged 25-45",
      brandPositioning: "Aspirational lifestyle and personal expression",
      visualLanguage: "Elegant, sophisticated, trend-setting",
      competitiveEdge: "Superior styling and aspirational appeal",
      psychologyTriggers: "Social status, self-expression, confidence",
      priceStyle: "Elegant serif typography with luxury appeal"
    },
    
    // Jewelry & Luxury
    jewelry: {
      style: "Luxury macro photography with dramatic lighting",
      shotType: "Extreme close-up with artistic composition",
      composition: "Central focus with radial balance, negative space utilization",
      idealBackground: "Deep black velvet or textured luxury surfaces",
      studioLighting: "Controlled dramatic lighting with precision spots",
      cameraSetup: "Full-frame DSLR with macro capabilities (Canon 5D Mark IV equivalent)",
      lensChoice: "100mm macro lens with 1:1 magnification capability",
      focalLength: "100mm macro for life-size reproduction",
      keyLight: "Focused LED panel with barn doors for precision",
      fillLight: "Large white card reflector for shadow detail",
      rimLight: "Fiber optic light for gemstone sparkle enhancement",
      backgroundLight: "None (pure black background preferred)",
      depthOfField: "f/8-f/11 for critical sharpness across product",
      colorGrading: "Rich, saturated colors emphasizing precious materials",
      contrastStyle: "High contrast for luxury appeal and sparkle",
      sharpeningApproach: "Micro-detail enhancement for craftsmanship visibility",
      finishingStyle: "Luxury retouching with enhanced reflections",
      aspectRatio: "1:1 square for premium presentation",
      visualWeight: "Product-centric with dramatic shadow play",
      marketTier: "Luxury to ultra-luxury segment",
      targetDemographic: "Affluent consumers and gift buyers",
      brandPositioning: "Exclusivity, craftsmanship, prestige",
      visualLanguage: "Dramatic, luxurious, precious",
      competitiveEdge: "Superior craftsmanship visibility and luxury appeal",
      psychologyTriggers: "Status, investment value, emotional significance",
      priceStyle: "Sophisticated gold-toned typography with luxury serif fonts"
    },
    
    // Technology & Electronics
    tech: {
      style: "Modern tech product photography with futuristic aesthetics",
      shotType: "Hero product shot with clean minimalist presentation",
      composition: "Minimalist composition with geometric precision",
      idealBackground: "Pure white infinity curve or subtle gradient",
      studioLighting: "Even, soft lighting eliminating harsh reflections",
      cameraSetup: "High-resolution DSLR with tilt-shift capabilities",
      lensChoice: "24-70mm zoom lens for versatile framing",
      focalLength: "50mm equivalent for natural perspective",
      keyLight: "Large octagonal softbox for even illumination",
      fillLight: "Bounce cards for shadow lifting",
      rimLight: "Strip light for edge definition",
      backgroundLight: "Even background illumination for seamless white",
      depthOfField: "f/8-f/11 for front-to-back sharpness",
      colorGrading: "Cool, clean color palette emphasizing technology",
      contrastStyle: "Moderate contrast with clean highlights",
      sharpeningApproach: "Precision sharpening on technical details",
      finishingStyle: "Clean, minimal retouching maintaining authenticity",
      aspectRatio: "16:9 landscape for tech presentation standards",
      visualWeight: "Centered product with balanced negative space",
      marketTier: "Mid-range to premium technology segment",
      targetDemographic: "Tech enthusiasts and professionals",
      brandPositioning: "Innovation, reliability, cutting-edge technology",
      visualLanguage: "Clean, modern, sophisticated",
      competitiveEdge: "Technical superiority and innovative design",
      psychologyTriggers: "Innovation, efficiency, professional success",
      priceStyle: "Modern sans-serif typography with tech-inspired styling"
    },

    // Food & Beverage
    food: {
      style: "Commercial food photography with culinary artistry",
      shotType: "Hero food shot with appetizing composition",
      composition: "Overhead or 45-degree angle with garnish styling",
      idealBackground: "Rustic wood, marble, or clean white surfaces",
      studioLighting: "Natural window light simulation with warm tones",
      cameraSetup: "Full-frame camera with excellent color reproduction",
      lensChoice: "50mm or 85mm lens for natural food perspective",
      focalLength: "50-85mm for natural food proportions",
      keyLight: "Large softbox mimicking window light",
      fillLight: "White foam board reflectors for shadow control",
      rimLight: "Subtle back lighting for texture enhancement",
      backgroundLight: "Warm ambient lighting for atmosphere",
      depthOfField: "f/4-f/5.6 for selective focus on hero elements",
      colorGrading: "Warm, appetizing color palette enhancing freshness",
      contrastStyle: "Moderate contrast maintaining natural appearance",
      sharpeningApproach: "Careful sharpening preserving food texture",
      finishingStyle: "Natural enhancement maintaining food authenticity",
      aspectRatio: "1:1 or 4:5 for social media food presentation",
      visualWeight: "Hero food item with supporting elements",
      marketTier: "Artisan to premium food segment",
      targetDemographic: "Food enthusiasts and lifestyle consumers",
      brandPositioning: "Quality, freshness, culinary excellence",
      visualLanguage: "Warm, inviting, appetizing",
      competitiveEdge: "Superior food styling and freshness appeal",
      psychologyTriggers: "Hunger, comfort, indulgence, quality",
      priceStyle: "Warm, friendly typography matching food industry standards"
    },

    // Beauty & Cosmetics
    beauty: {
      style: "Luxury beauty product photography with glamour elements",
      shotType: "Product hero shot with lifestyle or model integration",
      composition: "Clean, sophisticated layout with premium styling",
      idealBackground: "Marble, silk textures, or pure gradient backgrounds",
      studioLighting: "Soft, flattering beauty lighting eliminating harsh shadows",
      cameraSetup: "High-resolution camera with excellent color accuracy",
      lensChoice: "85mm portrait lens for flattering compression",
      focalLength: "85-100mm for beauty product photography standards",
      keyLight: "Large beauty dish with diffusion for soft shadows",
      fillLight: "Reflector cards for even skin tone illumination",
      rimLight: "Hair light for model shots, edge light for products",
      backgroundLight: "Gradient lighting for sophisticated backgrounds",
      depthOfField: "f/5.6-f/8 for product sharpness with soft backgrounds",
      colorGrading: "Beauty-optimized color science with skin tone priority",
      contrastStyle: "Soft contrast maintaining luxury appeal",
      sharpeningApproach: "Selective sharpening on product details and textures",
      finishingStyle: "Beauty retouching with natural enhancement",
      aspectRatio: "4:5 portrait for beauty industry standards",
      visualWeight: "Product-focused with lifestyle elements",
      marketTier: "Premium to luxury beauty segment",
      targetDemographic: "Beauty-conscious consumers across age groups",
      brandPositioning: "Enhancement, self-care, luxury lifestyle",
      visualLanguage: "Soft, luxurious, aspirational",
      competitiveEdge: "Superior product presentation and lifestyle appeal",
      psychologyTriggers: "Self-improvement, confidence, luxury indulgence",
      priceStyle: "Elegant typography matching luxury beauty standards"
    },

    // Home & Lifestyle
    home: {
      style: "Interior lifestyle photography with contextual staging",
      shotType: "Lifestyle shot showing product in natural environment",
      composition: "Environmental context with product as focal point",
      idealBackground: "Styled interior spaces matching target demographic",
      studioLighting: "Natural light simulation with warm interior ambiance",
      cameraSetup: "Wide-angle capable camera for environmental context",
      lensChoice: "24-35mm wide-angle lens for interior spaces",
      focalLength: "24-35mm for environmental context and spatial relationships",
      keyLight: "Window light simulation with warm color temperature",
      fillLight: "Ambient interior lighting for natural atmosphere",
      rimLight: "Practical lighting from lamps and fixtures",
      backgroundLight: "Natural environmental lighting from interior sources",
      depthOfField: "f/8-f/11 for environmental sharpness and context",
      colorGrading: "Warm, inviting color palette suggesting comfort",
      contrastStyle: "Natural contrast matching real interior lighting",
      sharpeningApproach: "Environmental sharpening maintaining natural appearance",
      finishingStyle: "Lifestyle enhancement preserving authentic atmosphere",
      aspectRatio: "3:2 or 16:9 for environmental lifestyle presentation",
      visualWeight: "Balanced composition with product and environment",
      marketTier: "Mid-range to premium home goods segment",
      targetDemographic: "Homeowners and interior design enthusiasts",
      brandPositioning: "Comfort, style, lifestyle enhancement",
      visualLanguage: "Warm, inviting, aspirational living",
      competitiveEdge: "Superior lifestyle integration and contextual appeal",
      psychologyTriggers: "Comfort, status, lifestyle aspiration, home pride",
      priceStyle: "Friendly, approachable typography matching home industry"
    }
  };

  // Advanced category matching with comprehensive fallbacks
  if (category.match(/(saree|dress|clothing|fashion|apparel|shirt|pants|jacket|coat|skirt|blouse|kurta|lehenga|outfit|wear|textile|fabric)/)) {
    return baseSpecs.fashion;
  } else if (category.match(/(jewelry|jewellery|ring|necklace|earring|bracelet|chain|pendant|diamond|gold|silver|gem|ornament|watch|timepiece)/)) {
    return baseSpecs.jewelry;
  } else if (category.match(/(electronic|tech|gadget|phone|laptop|computer|device|smart|digital|gaming|hardware|software|camera|audio)/)) {
    return baseSpecs.tech;
  } else if (category.match(/(food|snack|beverage|drink|meal|recipe|cuisine|delicious|tasty|restaurant|cafe|bakery|dessert|sweet|organic|fresh)/)) {
    return baseSpecs.food;
  } else if (category.match(/(cosmetic|beauty|makeup|skincare|perfume|fragrance|cream|lotion|lipstick|foundation|serum|moisturizer)/)) {
    return baseSpecs.beauty;
  } else if (category.match(/(home|furniture|decor|interior|lamp|chair|table|sofa|bed|decoration|living|kitchen|lifestyle)/)) {
    return baseSpecs.home;
  } else {
    // Intelligent adaptive specs for unknown categories
    return {
      style: `Professional commercial photography specialized for ${category}`,
      shotType: "Professional product presentation optimized for category characteristics",
      composition: "Strategic composition emphasizing product unique selling points",
      idealBackground: "Category-appropriate background enhancing product appeal",
      studioLighting: "Professional lighting setup optimized for product materials",
      cameraSetup: "Professional camera system suitable for commercial photography",
      lensChoice: "Optimal lens selection for product characteristics",
      focalLength: "Appropriate focal length for flattering product presentation",
      keyLight: "Primary lighting optimized for product materials and textures",
      fillLight: "Balanced fill lighting for optimal detail visibility",
      rimLight: "Edge lighting for product separation and dimension",
      backgroundLight: "Background lighting complementing overall composition",
      depthOfField: "Optimal depth of field for product focus and background treatment",
      colorGrading: "Color treatment enhancing product natural characteristics",
      contrastStyle: "Contrast management optimized for product appeal",
      sharpeningApproach: "Detail enhancement appropriate for product type",
      finishingStyle: "Professional finishing suitable for commercial use",
      aspectRatio: "Optimal aspect ratio for product presentation",
      visualWeight: "Balanced composition emphasizing product importance",
      marketTier: "Mid to premium market positioning",
      targetDemographic: `Target audience appropriate for ${category}`,
      brandPositioning: `Quality and value proposition for ${category} market`,
      visualLanguage: `Aesthetic language appropriate for ${category} consumers`,
      competitiveEdge: `Unique advantages in ${category} marketplace`,
      psychologyTriggers: `Purchase motivators relevant to ${category} buyers`,
      priceStyle: "Professional typography appropriate for product category"
    };
  }
}

// Advanced scene analysis system
function analyzeSceneAdvanced(sceneDescription) {
  const scene = sceneDescription.toLowerCase();
  
  let environmentalContext = "";
  let lightingConsiderations = "";
  let compositionalStrategy = "";
  let moodAndAtmosphere = "";
  let technicalExecution = "";
  
  // Environment analysis
  if (scene.match(/(outdoor|nature|beach|mountain|forest|garden|park|street|city|urban)/)) {
    environmentalContext = "• Environmental Context: Outdoor setting requiring natural light integration and environmental harmony";
    lightingConsiderations = "• Lighting Strategy: Simulate natural daylight with consideration for time of day and weather conditions";
    compositionalStrategy = "• Composition: Integrate product naturally within environmental context using environmental leading lines";
    technicalExecution = "• Technical: Account for outdoor lighting variables, use graduated filters simulation, ensure product visibility";
  } else if (scene.match(/(indoor|home|office|studio|room|kitchen|bedroom|living|interior)/)) {
    environmentalContext = "• Environmental Context: Interior setting allowing controlled lighting and staged atmosphere";
    lightingConsiderations = "• Lighting Strategy: Blend artificial and natural interior lighting for authentic ambiance";
    compositionalStrategy = "• Composition: Use interior architecture and furnishing to frame and complement product";
    technicalExecution = "• Technical: Balance multiple light sources, maintain consistent color temperature, control reflections";
  } else if (scene.match(/(luxury|premium|elegant|sophisticated|high-end|exclusive|upscale)/)) {
    environmentalContext = "• Environmental Context: Luxury setting emphasizing premium materials and sophisticated design elements";
    lightingConsiderations = "• Lighting Strategy: Dramatic, high-quality lighting emphasizing luxury and exclusivity";
    compositionalStrategy = "• Composition: Sophisticated composition rules emphasizing prestige and aspiration";
    technicalExecution = "• Technical: Premium production values with attention to every detail and finish";
  } else if (scene.match(/(casual|everyday|lifestyle|normal|regular|daily|relaxed)/)) {
    environmentalContext = "• Environmental Context: Relatable, everyday setting that consumers can easily identify with";
    lightingConsiderations = "• Lighting Strategy: Natural, approachable lighting that feels authentic and unforced";
    compositionalStrategy = "• Composition: Comfortable, natural composition that doesn't feel overly staged";
    technicalExecution = "• Technical: Maintain professional quality while preserving authentic, lived-in atmosphere";
  } else {
    environmentalContext = `• Environmental Context: Custom environment interpretation of "${sceneDescription}" with creative adaptation`;
    lightingConsiderations = "• Lighting Strategy: Adaptive lighting approach matching scene requirements and mood";
    compositionalStrategy = "• Composition: Creative composition balancing scene integration with product prominence";
    technicalExecution = "• Technical: Flexible technical approach optimized for unique scene requirements";
  }
  
  // Mood and atmosphere analysis
  if (scene.match(/(romantic|love|intimate|soft|gentle|warm)/)) {
    moodAndAtmosphere = "• Mood: Romantic and intimate atmosphere with soft, warm emotional undertones";
  } else if (scene.match(/(professional|business|corporate|formal|executive)/)) {
    moodAndAtmosphere = "• Mood: Professional and authoritative atmosphere conveying competence and reliability";
  } else if (scene.match(/(fun|playful|energetic|vibrant|dynamic|exciting)/)) {
    moodAndAtmosphere = "• Mood: Energetic and playful atmosphere with dynamic visual elements and vibrant colors";
  } else if (scene.match(/(peaceful|calm|serene|tranquil|meditative|zen)/)) {
    moodAndAtmosphere = "• Mood: Peaceful and serene atmosphere promoting relaxation and mindfulness";
  } else {
    moodAndAtmosphere = `• Mood: Atmosphere carefully crafted to match "${sceneDescription}" emotional context`;
  }
  
  return {
    environmentalContext,
    lightingConsiderations,
    compositionalStrategy,
    moodAndAtmosphere,
    technicalExecution
  };
}

// AI-powered scene analysis for any scenario (handles null/undefined scenes)
function analyzeScene(sceneDescription) {
  if (!sceneDescription || !sceneDescription.trim()) {
    return {
      environmentNotes: "• Default environment: Create a clean, professional background suitable for the product",
      moodDirection: "• Mood: Professional, clean, product-focused",
      technicalConsiderations: "• Focus on optimal product presentation with neutral, complementary background"
    };
  }
  
  const scene = sceneDescription.toLowerCase();
  
  let environmentNotes = "";
  let moodDirection = "";
  let technicalConsiderations = "";
  
  // Analyze environment type
  if (scene.match(/(outdoor|nature|beach|mountain|forest|garden|park|street|city)/)) {
    environmentNotes = "• Outdoor environment: Use natural lighting, consider weather and environmental elements";
    technicalConsiderations = "• Account for natural lighting variations, ensure product visibility in outdoor settings";
  } else if (scene.match(/(indoor|home|office|studio|room|kitchen|bedroom|living)/)) {
    environmentNotes = "• Indoor environment: Utilize controlled interior lighting, focus on ambiance";
    technicalConsiderations = "• Balance artificial and natural light sources, maintain consistent exposure";
  } else if (scene.match(/(luxury|premium|elegant|sophisticated|high-end|exclusive)/)) {
    environmentNotes = "• Luxury setting: Emphasize premium materials, sophisticated styling elements";
    moodDirection = "• Mood: Aspirational, exclusive, high-end appeal";
  } else if (scene.match(/(casual|everyday|lifestyle|normal|regular|daily)/)) {
    environmentNotes = "• Lifestyle setting: Show realistic usage scenarios, relatable environments";
    moodDirection = "• Mood: Approachable, relatable, everyday appeal";
  } else if (scene.match(/(dramatic|artistic|creative|unique|unusual|abstract)/)) {
    environmentNotes = "• Creative setting: Embrace artistic interpretation while maintaining product focus";
    moodDirection = "• Mood: Artistic, creative, memorable impact";
    technicalConsiderations = "• Balance creative expression with commercial viability";
  } else {
    // Adaptive analysis for unique scenes
    environmentNotes = `• Custom environment: Adapt photography to suit the unique "${sceneDescription}" setting`;
    moodDirection = "• Mood: Tailored to complement the specific scene atmosphere";
    technicalConsiderations = "• Custom technical approach based on scene requirements";
  }
  
  return {
    environmentNotes,
    moodDirection,
    technicalConsiderations
  };
}

// Advanced AI-Powered Category Analysis and Adaptive Prompting System
function createAdvancedAdaptivePrompt(productCategory, sceneDescription = null, priceOverlay = null, referenceImageUrl) {
  const category = productCategory.toLowerCase();
  
  // Advanced category analysis with professional photography techniques
  let photographyDetails = getAdvancedPhotographySpecs(category);
  
  // Advanced scene integration analysis
  let sceneIntegration = "";
  let environmentalFactors = "";
  let compositionalGuidance = "";
  
  if (sceneDescription && sceneDescription.trim()) {
    const advancedSceneAnalysis = analyzeSceneAdvanced(sceneDescription);
    sceneIntegration = `
ADVANCED SCENE INTEGRATION: "${sceneDescription}"
${advancedSceneAnalysis.environmentalContext}
${advancedSceneAnalysis.lightingConsiderations}
${advancedSceneAnalysis.compositionalStrategy}
${advancedSceneAnalysis.moodAndAtmosphere}
${advancedSceneAnalysis.technicalExecution}`;
  } else {
    sceneIntegration = `
PREMIUM STUDIO SETUP FOR ${productCategory.toUpperCase()}:
• Create a sophisticated studio environment optimized for ${category} photography
• Use ${photographyDetails.idealBackground} that enhances product visibility
• Apply ${photographyDetails.studioLighting} for optimal product presentation
• Ensure contextual relevance to ${category} market positioning
• Maintain clean, professional aesthetic that emphasizes product quality`;
  }

  // Advanced price overlay integration
  let priceStrategy = "";
  if (priceOverlay && priceOverlay.trim()) {
    priceStrategy = `
STRATEGIC PRICE PRESENTATION: "${priceOverlay}"
• Design elegant price overlay using ${photographyDetails.priceStyle} aesthetic
• Position strategically to complement composition without product obstruction
• Use typography that matches ${category} market segment (${photographyDetails.marketTier})
• Ensure high contrast and readability against chosen background
• Apply subtle design elements that enhance perceived value
• Consider psychological pricing presentation for ${category} customers`;
  } else {
    priceStrategy = `
PURE PRODUCT FOCUS STRATEGY:
• Eliminate all commercial elements to showcase pure product appeal
• Create aspirational presentation that builds desire before price consideration
• Focus on premium aesthetic that justifies future pricing discussions
• Emphasize product quality, craftsmanship, and unique selling propositions
• Build emotional connection through visual storytelling`;
  }
  
  // Advanced technical specifications
  const technicalSpecs = `
ADVANCED TECHNICAL EXECUTION:
Camera & Lens Simulation:
• Simulate ${photographyDetails.cameraSetup} for authentic ${category} photography
• Apply ${photographyDetails.lensChoice} characteristics for optimal perspective
• Use ${photographyDetails.focalLength} equivalent for proper product proportions

Lighting Design:
• Primary: ${photographyDetails.keyLight} for main illumination
• Secondary: ${photographyDetails.fillLight} to control shadows and contrast
• Accent: ${photographyDetails.rimLight} for depth and separation
• Background: ${photographyDetails.backgroundLight} for environmental control

Post-Processing Pipeline:
• Color Grading: ${photographyDetails.colorGrading} to match ${category} aesthetics
• Contrast Management: ${photographyDetails.contrastStyle} for optimal visual impact
• Sharpening: ${photographyDetails.sharpeningApproach} suitable for ${category} details
• Final Polish: ${photographyDetails.finishingStyle} for commercial-grade output`;

  // Market positioning and brand strategy
  const marketingStrategy = `
MARKET POSITIONING & BRAND STRATEGY:
Target Audience: ${photographyDetails.targetDemographic}
Brand Positioning: ${photographyDetails.brandPositioning}
Visual Language: ${photographyDetails.visualLanguage}
Competitive Advantage: ${photographyDetails.competitiveEdge}
Purchase Psychology: ${photographyDetails.psychologyTriggers}`;

  // Build comprehensive advanced prompt
  const advancedPrompt = `
ADVANCED COMMERCIAL PRODUCT PHOTOGRAPHY BRIEF
=====================================================

PRODUCT ANALYSIS:
Category: ${productCategory}
Reference Image: ${referenceImageUrl}
Market Tier: ${photographyDetails.marketTier}
Photography Style: ${photographyDetails.style}

PHOTOGRAPHY SPECIFICATIONS:
Shot Type: ${photographyDetails.shotType}
Composition Rules: ${photographyDetails.composition}
Depth of Field: ${photographyDetails.depthOfField}
Aspect Ratio: ${photographyDetails.aspectRatio}
Visual Weight Distribution: ${photographyDetails.visualWeight}

${sceneIntegration}

${priceStrategy}

${technicalSpecs}

${marketingStrategy}

CREATIVE EXECUTION GUIDELINES:
• Maintain photorealistic quality with commercial polish
• Balance artistic creativity with marketing effectiveness
• Ensure scalability across different marketing channels
• Create memorable visual impact that drives engagement
• Apply advanced color psychology for ${category} market
• Incorporate subtle motion blur or dynamic elements where appropriate
• Use advanced depth mapping for realistic focus transitions

QUALITY ASSURANCE STANDARDS:
• Commercial photography grade output (suitable for advertising)
• High resolution with crisp product details
• Professional color accuracy and consistency
• Optimal file compression without quality loss
• Cross-platform compatibility for web and print usage

FINAL DIRECTIVE:
Generate a masterpiece-quality commercial product image that combines the uploaded ${productCategory} with advanced photography techniques, creating a visually stunning and commercially viable result that exceeds industry standards and drives maximum consumer appeal.`;

  return advancedPrompt;
}

// Gemini API call for Vercel Node.js with enhanced prompting and optional parameters
async function generateImageFromAi(productImageBase64, productCategory, sceneDescription = null, priceOverlay = null) {
  console.log('=== GENERATE IMAGE FROM AI ===');
  console.log('Parameters received:');
  console.log('- productImageBase64:', productImageBase64 ? 'present' : 'MISSING');
  console.log('- productCategory:', productCategory || 'MISSING');
  console.log('- sceneDescription:', sceneDescription || 'null (will use default)');
  console.log('- priceOverlay:', priceOverlay || 'null (will be omitted)');
  
  // Validate required parameters with enhanced checking
  if (!productImageBase64 || typeof productImageBase64 !== 'string' || productImageBase64.trim() === '') {
    throw new Error("Product image is required but not provided or is invalid");
  }
  
  if (!productCategory || typeof productCategory !== 'string' || productCategory.trim() === '') {
    throw new Error("Product category is required but not provided or is invalid");
  }

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error("Missing GEMINI_API_KEY environment variable");
  }

  console.log("Step 1: Uploading reference image to Supabase...");
  
  // First, upload the user's image to reference-photos bucket
  let referenceImageUrl;
  try {
    referenceImageUrl = await uploadReferenceImageToSupabase(productImageBase64);
    console.log("Reference image uploaded successfully:", referenceImageUrl);
  } catch (error) {
    console.error("Failed to upload reference image:", error);
    throw new Error(`Failed to process reference image: ${error.message}`);
  }

  console.log("Step 2: Creating enhanced prompt based on product category...");
  console.log(`Scene description: ${sceneDescription ? 'provided' : 'not provided (will use default)'}`);
  console.log(`Price overlay: ${priceOverlay ? 'provided' : 'not provided (will focus on product)'}`);
  
  // Create category-specific enhanced prompt with optional parameters
  const enhancedPrompt = createAdvancedAdaptivePrompt(productCategory, sceneDescription, priceOverlay, referenceImageUrl);
  console.log("Advanced enhanced prompt created for category:", productCategory);

  console.log("Step 3: Sending request to Gemini API with enhanced prompt...");

  // Use the Gemini REST API endpoint for image generation
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-image-preview:generateContent?key=${apiKey}`;

  // Build request body using enhanced prompt
  const requestBody = {
    contents: [
      {
        parts: [
          {
            text: enhancedPrompt
          },
          {
            inlineData: {
              mimeType: "image/jpeg",
              data: await getImageAsBase64FromUrl(referenceImageUrl)
            }
          }
        ]
      }
    ],
    generationConfig: {
      temperature: 0.8,
      maxOutputTokens: 1024,
      topP: 0.9,
      topK: 40
    }
  };

  console.log("Request structure:", JSON.stringify({
    contents: [
      {
        parts: [
          {
            text: "[ADVANCED_PROMPT_TRUNCATED]"
          },
          {
            inlineData: {
              mimeType: requestBody.contents[0].parts[1].inlineData.mimeType,
              data: "[BASE64_FROM_PUBLIC_URL]"
            }
          }
        ]
      }
    ],
    generationConfig: requestBody.generationConfig
  }, null, 2));

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(requestBody)
    });

    console.log("Response status:", response.status);

    if (!response.ok) {
      const errorText = await response.text();
      console.error("Gemini API error response:", errorText);
      try {
        const errorJson = JSON.parse(errorText);
        throw new Error(`Gemini API failed (${response.status}): ${JSON.stringify(errorJson, null, 2)}`);
      } catch (parseError) {
        throw new Error(`Gemini API failed (${response.status}): ${errorText}`);
      }
    }

    const responseData = await response.json();
    console.log("Gemini API response received");

    const candidate = responseData?.candidates?.[0];
    if (!candidate?.content?.parts) {
      throw new Error("No response parts found in Gemini API response");
    }

    console.log("Step 4: Processing generated image...");

    // Look for image data in response parts
    for (const part of candidate.content.parts) {
      if (part.inlineData) {
        const generatedMimeType = part.inlineData.mimeType;
        const generatedBase64 = part.inlineData.data;
        console.log("Image generated successfully, uploading to generated-images bucket...");
        
        // Upload generated image to generated-images bucket
        try {
          const publicUrl = await uploadGeneratedImageToSupabase(generatedBase64, generatedMimeType);
          console.log("Generated image uploaded successfully:", publicUrl);
          return publicUrl;
        } catch (uploadError) {
          console.error("Failed to upload generated image:", uploadError);
          // Fallback: return base64 (though it won't display in WhatsApp Flow)
          return `data:${generatedMimeType};base64,${generatedBase64}`;
        }
      }
    }

    // If no image found, check for text response (which might indicate an error)
    const textPart = candidate.content.parts.find((p) => p.text);
    if (textPart) {
      throw new Error(`Model returned text instead of image: ${textPart.text}`);
    }

    throw new Error("No image data found in Gemini API response");
  } catch (error) {
    console.error('Error in generateImageFromAi:', error);
    if (error.message.includes('fetch')) {
      throw new Error(`Network error calling Gemini API: ${error.message}`);
    }
    throw error;
  }
}

// --- Request Handlers ---
async function handleDataExchange(decryptedBody) {
  const { action, screen, data } = decryptedBody;
  console.log(`Processing action: ${action} for screen: ${screen}`);
  console.log('Full decrypted body:', JSON.stringify(decryptedBody, null, 2));
  console.log('Data received:', JSON.stringify(data, null, 2));

  if (action === 'INIT') {
    return {
      screen: 'COLLECT_INFO',
      data: {}
    };
  }

  // Handle data_exchange for any screen that has the required data
  if (action === 'data_exchange') {
    console.log('=== DATA EXCHANGE ACTION ===');
    console.log('Full decrypted body:', JSON.stringify(decryptedBody, null, 2));
    console.log('Data object:', JSON.stringify(data, null, 2));
    console.log('Available data keys:', data ? Object.keys(data) : 'No data object');
    console.log('============================');

    // Check if we have the required fields for image generation (only product_image and product_category mandatory)
    if (data && typeof data === 'object') {
      const { scene_description, price_overlay, product_image, product_category } = data;

      console.log('=== FIELD VALIDATION ===');
      console.log('product_image:', product_image ? 'present' : 'MISSING (REQUIRED)');
      console.log('product_category:', product_category ? `"${product_category}"` : 'MISSING (REQUIRED)');
      console.log('scene_description:', scene_description ? `"${scene_description}"` : 'not provided (optional)');
      console.log('price_overlay:', price_overlay ? `"${price_overlay}"` : 'not provided (optional)');
      console.log('========================');

      // Validate only mandatory fields: product_image and product_category
      if (!product_image) {
        console.log('❌ ERROR: Missing product_image');
        return {
          screen: 'COLLECT_IMAGE_SCENE',
          data: {
            error_message: "Product image is required. Please upload an image of your product."
          }
        };
      }

      if (!product_category || !product_category.trim()) {
        console.log('❌ ERROR: Missing product_category');
        return {
          screen: 'COLLECT_INFO',
          data: {
            error_message: "Product category is required. Please specify what type of product this is."
          }
        };
      }

      // Both required fields are present, determine generation type
      let generationType = "";
      if (scene_description && scene_description.trim() && price_overlay && price_overlay.trim()) {
        generationType = "Full featured image (Category + Scene + Price)";
      } else if (scene_description && scene_description.trim()) {
        generationType = "Scene integration (Category + Scene)";
      } else if (price_overlay && price_overlay.trim()) {
        generationType = "Price overlay (Category + Price)";
      } else {
        generationType = "Clean product shot (Category only)";
      }

      console.log('✅ All required fields present. Generation type:', generationType);
      console.log(`📱 Product Category: "${product_category}"`);
      console.log(`🖼️ Scene Description: ${scene_description && scene_description.trim() ? `"${scene_description}"` : 'Not provided - will use advanced studio setup'}`);
      console.log(`💰 Price Overlay: ${price_overlay && price_overlay.trim() ? `"${price_overlay}"` : 'Not provided - will focus on pure product appeal'}`);
      console.log('🚀 Proceeding with advanced AI generation...');
      
      try {
        const imageUrl = await generateImageFromAi(
          product_image, 
          product_category.trim(),
          scene_description && scene_description.trim() ? scene_description.trim() : null,
          price_overlay && price_overlay.trim() ? price_overlay.trim() : null
        );
        
        console.log('✅ Advanced image generation successful:', imageUrl);
        console.log(`🎯 Generated: ${generationType}`);
        return {
          screen: 'SUCCESS_SCREEN',
          data: {
            image_url: imageUrl
          }
        };
      } catch (e) {
        console.error('❌ Advanced image generation failed:', e);
        return {
          screen: 'COLLECT_IMAGE_SCENE',
          data: {
            error_message: `Image generation failed: ${e.message}. Please try again with a different image or check your inputs.`
          }
        };
      }
    } else {
      console.log('No data object found in request');
      return {
        screen: 'COLLECT_INFO',
        data: {
          error_message: 'No data received. Please fill in the form.'
        }
      };
    }
  }

  if (action === 'BACK') {
    if (screen === 'COLLECT_IMAGE_SCENE') {
      return {
        screen: 'COLLECT_INFO',
        data: {}
      };
    }
    // Handle other back navigation
    return {
      screen: 'COLLECT_INFO',
      data: {}
    };
  }

  console.log(`Unhandled action/screen combination: ${action}/${screen}`);
  return {
    screen: 'COLLECT_INFO',
    data: {
      error_message: 'An unexpected error occurred.'
    }
  };
}

async function handleHealthCheck() {
  return {
    data: {
      status: 'active'
    }
  };
}

async function handleErrorNotification(decryptedBody) {
  console.log('Error notification received:', decryptedBody);
  return {
    data: {
      acknowledged: true
    }
  };
}

// --- Main Vercel API Handler ---
export default async function handler(req, res) {
  // Handle CORS
  if (req.method === 'OPTIONS') {
    res.status(200);
    Object.entries(corsHeaders).forEach(([key, value]) => {
      res.setHeader(key, value);
    });
    return res.end();
  }

  // Set CORS headers for all responses
  Object.entries(corsHeaders).forEach(([key, value]) => {
    res.setHeader(key, value);
  });

  try {
    validateEnvironmentVars();
  } catch (error) {
    console.error('Environment validation failed:', error.message);
    return res.status(500).json({ error: 'Internal Server Error' });
  }

  if (req.method === 'GET') {
    const { query } = req;
    const mode = query['hub.mode'];
    const token = query['hub.verify_token'];
    const challenge = query['hub.challenge'];
    const verifyToken = process.env.VERIFY_TOKEN;

    if (mode === 'subscribe' && token === verifyToken && challenge) {
      res.setHeader('Content-Type', 'text/plain');
      return res.status(200).send(challenge);
    } else {
      return res.status(403).json({ error: 'Forbidden' });
    }
  }

  if (req.method === 'POST') {
    try {
      const requestBody = req.body;

      const privateKeyPem = process.env.PRIVATE_KEY;
      const privateKey = await importPrivateKey(privateKeyPem);

      const { decryptedBody, aesKeyBuffer, initialVectorBuffer } = await decryptRequest(requestBody, privateKey);

      let responsePayload;
      if (decryptedBody.action === 'ping') {
        responsePayload = await handleHealthCheck();
      } else if (decryptedBody.action === 'error_notification') {
        responsePayload = await handleErrorNotification(decryptedBody);
      } else {
        responsePayload = await handleDataExchange(decryptedBody);
      }

      const encryptedResponse = await encryptResponse(responsePayload, aesKeyBuffer, initialVectorBuffer);

      // WhatsApp expects just the encrypted string as the response body
      res.setHeader('Content-Type', 'application/json');
      return res.status(200).send(encryptedResponse);
    } catch (error) {
      console.error('Error processing request:', error);
      return res.status(500).json({ error: `Internal Server Error: ${error.message}` });
    }
  }

  return res.status(405).json({ error: 'Method Not Allowed' });
}

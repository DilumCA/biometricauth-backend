

import axios from 'axios';

// Set this to true to use mock IP addresses for testing
const USE_MOCK_IP = false;

// A collection of mock IPs for testing
const MOCK_IPS = [
  { ip: '8.8.8.8', city: 'Mountain View', region: 'California', country_name: 'United States', latitude: 37.386, longitude: -122.0838 },
  { ip: '50.21.183.44', city: 'New York', region: 'New York', country_name: 'United States', latitude: 40.7128, longitude: -74.006 },
  { ip: '109.169.23.123', city: 'London', region: 'England', country_name: 'United Kingdom', latitude: 51.5074, longitude: -0.1278 },
  { ip: '103.10.197.50', city: 'Tokyo', region: 'Tokyo', country_name: 'Japan', latitude: 35.6762, longitude: 139.6503 }
];

let mockIPIndex = 0;

// Use this to cycle through different mock IPs for testing
export const getNextMockIP = () => {
  const mockIP = MOCK_IPS[mockIPIndex];
  mockIPIndex = (mockIPIndex + 1) % MOCK_IPS.length;
  return mockIP;
};

export const getLocationFromIP = async (ip) => {
  try {
        // Special case for local/internal testing
    if (ip === '::1' || ip === '127.0.0.1' || 
        ip.startsWith('10.') || ip.startsWith('172.') || 
        ip.startsWith('192.168.') || ip.includes('railway.internal')) {
      console.log('Using mock location for internal IP:', ip);
      return {
        city: 'Colombo',
        region: 'Western Province',
        country_name: 'Sri Lanka',
        latitude: 6.9271,
        longitude: 79.8612
      };
    }
    if (USE_MOCK_IP) {
      // For local testing, use a mock IP location
      const mockIP = getNextMockIP();
      console.log(`Using mock IP location: ${mockIP.city}, ${mockIP.country_name}`);
      return mockIP;
    }
    
    // Using a free IP geolocation API for real requests
    const response = await axios.get(`https://ipapi.co/${ip}/json/`);
    
    if (response.data && response.data.city) {
      return response.data;
    }
    
    return null;
  } catch (error) {
    console.error('Failed to get location from IP:', error);
    return null;
  }
};
/**
 * Calculate the distance between two coordinates using the Haversine formula
 * @param {number} lat1 - Latitude of first point in degrees
 * @param {number} lon1 - Longitude of first point in degrees
 * @param {number} lat2 - Latitude of second point in degrees
 * @param {number} lon2 - Longitude of second point in degrees
 * @returns {number} Distance in kilometers
 */
export const calculateDistance = (lat1, lon1, lat2, lon2) => {
  // Earth's radius in kilometers
  const R = 6371;
  
  // Convert latitude and longitude from degrees to radians
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  
  // Haversine formula
  const a = 
    Math.sin(dLat/2) * Math.sin(dLat/2) +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * 
    Math.sin(dLon/2) * Math.sin(dLon/2);
  
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  const distance = R * c; // Distance in kilometers
  
  return distance;
};

/**
 * Check if travel between two locations is plausible given the time elapsed
 * @param {object} lastLocation - Object containing lat/lon of previous login
 * @param {object} currentLocation - Object containing lat/lon of current login
 * @param {Date} lastTime - Timestamp of previous login
 * @param {Date} currentTime - Timestamp of current login
 * @returns {object} Result with plausibility and details
 */
export const isTravelPlausible = (lastLocation, currentLocation, lastTime, currentTime) => {
  // If location data is missing, we can't make a determination
  if (!lastLocation?.latitude || !lastLocation?.longitude || 
      !currentLocation?.latitude || !currentLocation?.longitude) {
    return { plausible: true, reason: 'incomplete_data' };
  }
  
  // Calculate distance between the two points
  const distance = calculateDistance(
    lastLocation.latitude, lastLocation.longitude,
    currentLocation.latitude, currentLocation.longitude
  );
  
  // If distance is small (less than 50km), it's always plausible
  if (distance < 50) {
    return { plausible: true, reason: 'nearby_location', distance };
  }
  
  // Calculate time elapsed in hours
  const timeElapsed = (currentTime - lastTime) / (1000 * 60 * 60);
  
  // Define travel speed thresholds (km/h)
  const SPEEDS = {
    CAR: 60,      // Average fast car travel speed
    TRAIN: 150,     // High-speed train
    PLANE: 450      // Commercial airplane
  };
  
  // Calculate required speed
  const requiredSpeed = distance / timeElapsed;
  
  // Determine if travel is plausible
  if (requiredSpeed > SPEEDS.PLANE) {
    return { 
      plausible: false, 
      reason: 'impossible_travel',
      distance,
      timeElapsed,
      requiredSpeed
    };
  } else if (requiredSpeed > SPEEDS.TRAIN) {
    return { 
      plausible: true, 
      reason: 'air_travel_required',
      distance,
      timeElapsed,
      requiredSpeed
    };
  } else if (requiredSpeed > SPEEDS.CAR) {
    return { 
      plausible: true, 
      reason: 'fast_transport_required',
      distance,
      timeElapsed,
      requiredSpeed
    };
  }
  
  return { plausible: true, reason: 'normal_travel', distance, timeElapsed, requiredSpeed };
};
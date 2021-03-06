'use strict';

var QueryFile = require('pg-promise').QueryFile;

var path = require('path');

module.exports = {
  array: {
    add: sql('array/add.sql'),
    addUnique: sql('array/add-unique.sql'),
    contains: sql('array/contains.sql'),
    containsAll: sql('array/contains-all.sql'),
    containsAllRegex: sql('array/contains-all-regex.sql'),
    remove: sql('array/remove.sql')
  },
  misc: {
    jsonObjectSetKeys: sql('misc/json-object-set-keys.sql')
  }
}; ///////////////////////////////////////////////
// Helper for linking to external query files;

function sql(file) {
  var fullPath = path.join(__dirname, file); // generating full path;

  var qf = new QueryFile(fullPath, {
    minify: true
  });

  if (qf.error) {
    throw qf.error;
  }

  return qf;
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uLy4uL3NyYy9BZGFwdGVycy9TdG9yYWdlL1Bvc3RncmVzL3NxbC9pbmRleC5qcyJdLCJuYW1lcyI6WyJRdWVyeUZpbGUiLCJyZXF1aXJlIiwicGF0aCIsIm1vZHVsZSIsImV4cG9ydHMiLCJhcnJheSIsImFkZCIsInNxbCIsImFkZFVuaXF1ZSIsImNvbnRhaW5zIiwiY29udGFpbnNBbGwiLCJjb250YWluc0FsbFJlZ2V4IiwicmVtb3ZlIiwibWlzYyIsImpzb25PYmplY3RTZXRLZXlzIiwiZmlsZSIsImZ1bGxQYXRoIiwiam9pbiIsIl9fZGlybmFtZSIsInFmIiwibWluaWZ5IiwiZXJyb3IiXSwibWFwcGluZ3MiOiJBQUFBOztBQUVBLElBQUlBLFNBQVMsR0FBR0MsT0FBTyxDQUFDLFlBQUQsQ0FBUCxDQUFzQkQsU0FBdEM7O0FBQ0EsSUFBSUUsSUFBSSxHQUFHRCxPQUFPLENBQUMsTUFBRCxDQUFsQjs7QUFFQUUsTUFBTSxDQUFDQyxPQUFQLEdBQWlCO0FBQ2ZDLEVBQUFBLEtBQUssRUFBRTtBQUNMQyxJQUFBQSxHQUFHLEVBQUVDLEdBQUcsQ0FBQyxlQUFELENBREg7QUFFTEMsSUFBQUEsU0FBUyxFQUFFRCxHQUFHLENBQUMsc0JBQUQsQ0FGVDtBQUdMRSxJQUFBQSxRQUFRLEVBQUVGLEdBQUcsQ0FBQyxvQkFBRCxDQUhSO0FBSUxHLElBQUFBLFdBQVcsRUFBRUgsR0FBRyxDQUFDLHdCQUFELENBSlg7QUFLTEksSUFBQUEsZ0JBQWdCLEVBQUVKLEdBQUcsQ0FBQyw4QkFBRCxDQUxoQjtBQU1MSyxJQUFBQSxNQUFNLEVBQUVMLEdBQUcsQ0FBQyxrQkFBRDtBQU5OLEdBRFE7QUFTZk0sRUFBQUEsSUFBSSxFQUFFO0FBQ0pDLElBQUFBLGlCQUFpQixFQUFFUCxHQUFHLENBQUMsK0JBQUQ7QUFEbEI7QUFUUyxDQUFqQixDLENBY0E7QUFDQTs7QUFDQSxTQUFTQSxHQUFULENBQWFRLElBQWIsRUFBbUI7QUFDakIsTUFBSUMsUUFBUSxHQUFHZCxJQUFJLENBQUNlLElBQUwsQ0FBVUMsU0FBVixFQUFxQkgsSUFBckIsQ0FBZixDQURpQixDQUMwQjs7QUFFM0MsTUFBSUksRUFBRSxHQUFHLElBQUluQixTQUFKLENBQWNnQixRQUFkLEVBQXdCO0FBQUVJLElBQUFBLE1BQU0sRUFBRTtBQUFWLEdBQXhCLENBQVQ7O0FBRUEsTUFBSUQsRUFBRSxDQUFDRSxLQUFQLEVBQWM7QUFDWixVQUFNRixFQUFFLENBQUNFLEtBQVQ7QUFDRDs7QUFFRCxTQUFPRixFQUFQO0FBQ0QiLCJzb3VyY2VzQ29udGVudCI6WyIndXNlIHN0cmljdCc7XG5cbnZhciBRdWVyeUZpbGUgPSByZXF1aXJlKCdwZy1wcm9taXNlJykuUXVlcnlGaWxlO1xudmFyIHBhdGggPSByZXF1aXJlKCdwYXRoJyk7XG5cbm1vZHVsZS5leHBvcnRzID0ge1xuICBhcnJheToge1xuICAgIGFkZDogc3FsKCdhcnJheS9hZGQuc3FsJyksXG4gICAgYWRkVW5pcXVlOiBzcWwoJ2FycmF5L2FkZC11bmlxdWUuc3FsJyksXG4gICAgY29udGFpbnM6IHNxbCgnYXJyYXkvY29udGFpbnMuc3FsJyksXG4gICAgY29udGFpbnNBbGw6IHNxbCgnYXJyYXkvY29udGFpbnMtYWxsLnNxbCcpLFxuICAgIGNvbnRhaW5zQWxsUmVnZXg6IHNxbCgnYXJyYXkvY29udGFpbnMtYWxsLXJlZ2V4LnNxbCcpLFxuICAgIHJlbW92ZTogc3FsKCdhcnJheS9yZW1vdmUuc3FsJyksXG4gIH0sXG4gIG1pc2M6IHtcbiAgICBqc29uT2JqZWN0U2V0S2V5czogc3FsKCdtaXNjL2pzb24tb2JqZWN0LXNldC1rZXlzLnNxbCcpLFxuICB9LFxufTtcblxuLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9cbi8vIEhlbHBlciBmb3IgbGlua2luZyB0byBleHRlcm5hbCBxdWVyeSBmaWxlcztcbmZ1bmN0aW9uIHNxbChmaWxlKSB7XG4gIHZhciBmdWxsUGF0aCA9IHBhdGguam9pbihfX2Rpcm5hbWUsIGZpbGUpOyAvLyBnZW5lcmF0aW5nIGZ1bGwgcGF0aDtcblxuICB2YXIgcWYgPSBuZXcgUXVlcnlGaWxlKGZ1bGxQYXRoLCB7IG1pbmlmeTogdHJ1ZSB9KTtcblxuICBpZiAocWYuZXJyb3IpIHtcbiAgICB0aHJvdyBxZi5lcnJvcjtcbiAgfVxuXG4gIHJldHVybiBxZjtcbn1cbiJdfQ==
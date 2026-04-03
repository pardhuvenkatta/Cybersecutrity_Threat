
let map;
let geojsonLayer;
let db = null;
let dbReady = false;
let SQL; 
window.currentThreatData = {};

function getColor(d) {
  return d > 1000 ? '#ff6060' : 
    d > 400 ? '#ffaa40' : 
      d > 0 ? '#00ff88' : 
        '#2c3e50';  
}

function styleMap(feature) {
  const countryCode = feature.id; 
  const threatCount = window.currentThreatData[countryCode] || 0;

  return {
    fillColor: getColor(threatCount),
    weight: 1,
    opacity: 1,
    color: 'rgba(0, 255, 136, 0.4)', 
    fillOpacity: 0.7
  };
}

function onEachFeature(feature, layer) {
  layer.on({
    mouseover: (e) => {
      const countryCode = feature.id;
      const count = window.currentThreatData[countryCode] || 0;
      const level = count > 1000 ? 'HIGH' : count > 400 ? 'MODERATE' : count > 0 ? 'LOW' : 'NONE';

      const tooltipContent = `
              <div style="font-family:'Share Tech Mono', monospace; font-size:12px;">
                <strong style="color:#00cfff;font-size:14px;">${feature.properties.name}</strong><br/>
                Threat Incidents: <span style="color:${getColor(count)}">${count}</span><br/>
                Risk Level: <span style="color:${getColor(count)}">${level}</span>
              </div>
            `;
      layer.bindTooltip(tooltipContent, { direction: 'top', sticky: true }).openTooltip();
      layer.setStyle({ fillOpacity: 1, weight: 2, color: '#00cfff' });
    },
    mouseout: (e) => {
      if (geojsonLayer) geojsonLayer.resetStyle(e.target);
      layer.closeTooltip();
    }
  });
}

async function initSqlModule() {
  const config = {
    locateFile: file => `vendor/${file}`
  };
  try {
    SQL = await window.initSqlJs(config);
    console.log("SQL.js WASM loaded successfully. Waiting for file upload...");
  } catch (err) {
    console.error("SQL.js Init Error:", err);
  }
}

function handleDbUpload(event) {
  const file = event.target.files[0];
  if (!file) return;

  if (file.name.toLowerCase().endsWith('.csv')) {
    Papa.parse(file, {
      header: true,
      skipEmptyLines: true,
      complete: function (results) {
        db = new SQL.Database();
        db.run(`
          CREATE TABLE threats (
            dt_year TEXT, dt_month TEXT, dt_day TEXT,
            dt_hour TEXT, country_code TEXT, threat_level INTEGER
          );
        `);

        db.run("BEGIN TRANSACTION;");
        const stmt = db.prepare("INSERT INTO threats (dt_year, dt_month, dt_day, dt_hour, country_code, threat_level) VALUES (?, ?, ?, ?, ?, ?)");

        for (let row of results.data) {
          const y = row.dt_year || row.year || row.Year || row.Date || "";
          const m = row.dt_month || row.month || row.Month || "";
          const d = row.dt_day || row.day || row.Day || "";
          const h = row.dt_hour || row.hour || row.Hour || row.Time || "";
          const c = row.country_code || row.country || row.Country || row.iso || row.ISO || "";
          let tl = row.threat_level || row.threat || row.severity || row.Severity || row.level || "0";

          stmt.run([y.toString(), m.toString(), d.toString(), h.toString(), c.toString().toUpperCase(), parseInt(tl)]);
        }
        stmt.free();
        db.run("COMMIT TRANSACTION;");
        dbReady = true;
        console.log("Uploaded CSV loaded into SQL memory successfully.");
        alert("CSV Dataset Loaded Successfully!");
        updateMapData();
      },
      error: function (err) {
        alert("Error parsing CSV: " + err.message);
      }
    });
  } else {
    // Process SQLite
    const reader = new FileReader();
    reader.onload = function () {
      const Uints = new Uint8Array(reader.result);
      db = new SQL.Database(Uints);
      dbReady = true;
      console.log("Uploaded database loaded successfully.");
      alert("SQLite Database Loaded Successfully!");
      updateMapData();
    };
    reader.readAsArrayBuffer(file);
  }
}

async function autoLoadDatabase() {
  try {
    const response = await fetch('map/data/threats.sqlite');
    const buffer = await response.arrayBuffer();
    const Uints = new Uint8Array(buffer);
    db = new SQL.Database(Uints);
    dbReady = true;
    console.log("Default database loaded successfully.");
    updateMapData();
  } catch (err) {
    console.warn("No default database found at map/data/threats.sqlite. User must upload manually.", err);
  }
}

function updateMapData() {
  if (!dbReady) {
    console.warn("Database not ready for filtering.");
    return;
  }

  const y = document.getElementById('mapYear').value;
  const m = document.getElementById('mapMonth').value;
  const d = document.getElementById('mapDay').value;
  const h = document.getElementById('mapHour').value;

  const query = `
    SELECT country_code, SUM(threat_level) as total_threat
    FROM threats
    WHERE dt_year = ? AND dt_month = ? AND dt_day = ? AND dt_hour = ?
    GROUP BY country_code;
  `;

  try {
    const stmt = db.prepare(query);
    stmt.bind([y, m, d, h]);

    let mapData = {};
    while (stmt.step()) {
      const row = stmt.getAsObject();
      mapData[row.country_code] = row.total_threat;
    }
    stmt.free();

    window.currentThreatData = mapData;
    console.log(`Map updated via Uploaded DB. ${Object.keys(mapData).length} targeted countries found.`);

    if (geojsonLayer) {
      geojsonLayer.eachLayer(function (layer) {
        geojsonLayer.resetStyle(layer);
      });
    }
  } catch (e) {
    console.error("SQL Execution Error. Ensure your uploaded DB has the 'threats' table with correct schema.", e);
    alert("Error executing query. Does your uploaded database have the correct schema?");
  }
}

function initMap() {
  if (!document.getElementById('map')) return;

  map = L.map('map', {
    center: [20, 0],
    zoom: 2,
    minZoom: 2,
    maxZoom: 6,
    zoomControl: false,
    attributionControl: false
  });

  // Remove loading overlay immediately after initialization
  const overlay = document.getElementById('map-loading-overlay');
  if (overlay) overlay.remove();

  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_nolabels/{z}/{x}/{y}{r}.png', {
    subdomains: 'abcd',
    maxZoom: 19
  }).addTo(map);

  fetch('vendor/countries.geo.json')
    .then(res => res.json())
    .then(data => {
      geojsonLayer = L.geoJson(data, {
        style: styleMap,
        onEachFeature: onEachFeature
      }).addTo(map);
    })
    .catch(err => console.error("Error loading GeoJSON: ", err));
}

document.addEventListener("DOMContentLoaded", async () => {
  initMap();
  await initSqlModule();
  autoLoadDatabase();
});

// Helper conversions
const fToC = f => Math.round(((f - 32) * 5) / 9);
const cToF = c => Math.round((c * 9) / 5 + 32);
const round = n => Math.round(n);

const els = {
  lat: document.getElementById('lat'),
  lon: document.getElementById('lon'),
  btn: document.getElementById('getWeather'),
  status: document.getElementById('status'),
  location: document.getElementById('location'),
  placeText: document.getElementById('placeText'),
  current: document.getElementById('current'),
  tempF: document.getElementById('tempF'),
  tempC: document.getElementById('tempC'),
  obsMeta: document.getElementById('obsMeta'),
  forecast: document.getElementById('forecast'),
  forecastGrid: document.getElementById('forecastGrid')
};

function setStatus(msg) {
  els.status.textContent = msg || '';
}

function show(el) { el.hidden = false; }
function hide(el) { el.hidden = true; }

async function getJSON(url) {
  const res = await fetch(url, { headers: { 'Accept': 'application/geo+json' } });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  return res.json();
}

async function getWeather() {
  hide(els.location); hide(els.current); hide(els.forecast);
  els.forecastGrid.innerHTML = '';
  setStatus('Looking up grid & stations…');

  const lat = parseFloat(els.lat.value);
  const lon = parseFloat(els.lon.value);
  if (Number.isNaN(lat) || Number.isNaN(lon)) {
    setStatus('Please enter a valid latitude and longitude.');
    return;
  }

  try {
    // 1) Resolve point -> forecast URL + relative location + station list
    const pointsUrl = `https://api.weather.gov/points/${lat.toFixed(4)},${lon.toFixed(4)}`;
    const points = await getJSON(pointsUrl);

    const forecastUrl = points.properties.forecast;
    const rel = points.properties.relativeLocation?.properties;
    const place = rel ? `${rel.city}, ${rel.state}` : `Lat ${lat.toFixed(2)}, Lon ${lon.toFixed(2)}`;

    els.placeText.textContent = place;
    show(els.location);

    // 2) Current observations: take the first station
    setStatus('Fetching current observation…');
    const stationsUrl = points.properties.observationStations;
    const stations = await getJSON(stationsUrl);
    const firstStation = stations?.features?.[0]?.id;
    let cNow = null, meta = '';

    if (firstStation) {
      const latestObsUrl = `${firstStation}/observations/latest`;
      const latest = await getJSON(latestObsUrl);
      const tC = latest?.properties?.temperature?.value; // Celsius (may be null)
      if (tC != null) {
        cNow = tC;
        const fNow = cToF(cNow);
        els.tempC.textContent = `${round(cNow)} °C`;
        els.tempF.textContent = `${round(fNow)} °F`;
      } else {
        // Sometimes temperature missing — fall back on forecast first period
        meta += 'Observation temperature unavailable; using forecast fallback. ';
      }
      const when = latest?.properties?.timestamp;
      if (when) meta += `Updated ${new Date(when).toLocaleString()}`;
    } else {
      meta = 'No station found; using forecast fallback.';
    }

    // 3) 7-day forecast (daytime highs) and fallback current temp if needed
    setStatus('Fetching 7‑day forecast…');
    const forecast = await getJSON(forecastUrl);
    const periods = forecast?.properties?.periods || [];
    const dayPeriods = periods.filter(p => p.isDaytime).slice(0, 7);

    // If no current observation temp, derive from first daytime period (Fahrenheit)
    if (cNow == null && dayPeriods.length) {
      const f = dayPeriods[0].temperature; // F
      els.tempF.textContent = `${round(f)} °F`;
      els.tempC.textContent = `${fToC(f)} °C`;
    }
    show(els.current);
    els.obsMeta.textContent = meta.trim();

    // Render day cards
    dayPeriods.forEach(p => {
      const name = p.name; // e.g., "Monday"
      const tempF = p.temperature;
      const tempC = fToC(tempF);
      const cond = p.shortForecast;

      const card = document.createElement('div');
      card.className = 'day-card';
      card.innerHTML = `
        <div class="day-name">${name}</div>
        <div class="temp-line">
          <div>${tempF}&nbsp;°F</div>
          <div>/</div>
          <div>${tempC}&nbsp;°C</div>
        </div>
        <div class="conditions">${cond}</div>
      `;
      els.forecastGrid.appendChild(card);
    });
    show(els.forecast);
    setStatus('');
  } catch (err) {
    console.error(err);
    setStatus('Error fetching data. Make sure the coordinates are within the U.S. and try again.');
  }
}

els.btn.addEventListener('click', getWeather);

// Basic convenience: prefill sample US coordinates (Midway, CA) for demo
els.lat.value = "33.7444864";
els.lon.value = "-117.9544";

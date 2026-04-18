import json
import os
import time as time_module
from collections import Counter
from datetime import datetime, time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
SETTINGS_PATH = DATA_DIR / "settings.json"
SUSPECTS_PATH = DATA_DIR / "suspect_users.json"
SAMPLE_LOGS_PATH = BASE_DIR / "logs_input.txt"
PORTAL_PATH = BASE_DIR / "portal.html"

DEFAULT_SETTINGS = {
	"off_hours": {
		"start": "00:00",
		"end": "04:00",
	}
}

DEFAULT_SUSPECTS = {
	"users": ["guest"]
}

CRITICAL_EVENTS = {"DELETE", "EXPORT"}
KNOWN_EVENTS = {"LOGIN", "ACCESS", "QUERY", "EXPORT", "DELETE"}


def ensure_data_files() -> None:
	DATA_DIR.mkdir(parents=True, exist_ok=True)

	if not SETTINGS_PATH.exists():
		SETTINGS_PATH.write_text(
			json.dumps(DEFAULT_SETTINGS, ensure_ascii=False, indent=2),
			encoding="utf-8",
		)

	if not SUSPECTS_PATH.exists():
		SUSPECTS_PATH.write_text(
			json.dumps(DEFAULT_SUSPECTS, ensure_ascii=False, indent=2),
			encoding="utf-8",
		)


def load_json(path: Path, fallback: dict) -> dict:
	try:
		return json.loads(path.read_text(encoding="utf-8"))
	except Exception:
		return fallback


def save_json(path: Path, payload: dict) -> None:
	path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def load_settings() -> dict:
	data = load_json(SETTINGS_PATH, DEFAULT_SETTINGS)
	off = data.get("off_hours", {})
	start = off.get("start", DEFAULT_SETTINGS["off_hours"]["start"])
	end = off.get("end", DEFAULT_SETTINGS["off_hours"]["end"])
	return {"off_hours": {"start": start, "end": end}}


def load_suspects() -> list[str]:
	data = load_json(SUSPECTS_PATH, DEFAULT_SUSPECTS)
	users = data.get("users", [])
	if not isinstance(users, list):
		return []
	return [str(u).strip().lower() for u in users if str(u).strip()]


def normalize_suspects(users: list) -> list[str]:
	normalized = []
	for user in users:
		name = str(user).strip().lower()
		if not name:
			continue
		if name not in normalized:
			normalized.append(name)
	return normalized


def save_suspects(users: list) -> None:
	payload = {"users": normalize_suspects(users)}
	save_json(SUSPECTS_PATH, payload)


def validate_time_value(value: str) -> bool:
	try:
		datetime.strptime(value, "%H:%M")
		return True
	except ValueError:
		return False


def validate_time_range(start: str, end: str) -> tuple[bool, str]:
	if not (validate_time_value(start) and validate_time_value(end)):
		return False, "Formato inválido. Usa HH:MM en 24 horas."
	if start == end:
		return False, "El inicio y fin no pueden ser iguales."
	return True, "ok"


def parse_time(value: str) -> time:
	return datetime.strptime(value, "%H:%M").time()


def is_time_in_range(target: time, start: time, end: time) -> bool:
	if start <= end:
		return start <= target <= end
	return target >= start or target <= end


def parse_log_line(line: str) -> dict:
	raw = line.strip()
	if not raw:
		return {"is_valid": False, "raw": line, "error": "Línea vacía"}
	if "\x00" in line:
		return {"is_valid": False, "raw": raw, "error": "Contiene caracteres no permitidos"}

	parts = [p.strip() for p in raw.split("|")]
	if len(parts) < 3:
		return {"is_valid": False, "raw": raw, "error": "Formato incompleto"}

	timestamp_raw = parts[0]
	try:
		ts = datetime.strptime(timestamp_raw, "%Y-%m-%d %H:%M:%S")
	except ValueError:
		return {
			"is_valid": False,
			"raw": raw,
			"error": "Fecha/hora inválida",
		}

	event = parts[1].upper()
	if not event:
		return {"is_valid": False, "raw": raw, "error": "Evento vacío"}
	if event not in KNOWN_EVENTS:
		return {"is_valid": False, "raw": raw, "error": f"Evento no soportado: {event}"}

	detail_items = parts[2:]
	detail_text = " | ".join(detail_items) if detail_items else ""
	if not detail_text.strip():
		return {"is_valid": False, "raw": raw, "error": "Detalle vacío"}

	user = None
	ip = None
	for item in detail_items:
		if item.lower().startswith("user="):
			user = item.split("=", 1)[1].strip()
		if item.lower().startswith("ip="):
			ip = item.split("=", 1)[1].strip()

	if event == "LOGIN":
		if not user:
			return {"is_valid": False, "raw": raw, "error": "LOGIN requiere campo user"}
		if not ip:
			return {"is_valid": False, "raw": raw, "error": "LOGIN requiere campo ip"}

	return {
		"is_valid": True,
		"raw": raw,
		"timestamp": ts,
		"timestamp_str": ts.strftime("%Y-%m-%d %H:%M:%S"),
		"event": event,
		"detail_text": detail_text,
		"details": detail_items,
		"user": user,
		"ip": ip,
	}


def analyze_logs(log_lines: list[str]) -> dict:
	# Etapa 0: Cargar configuración de análisis.
	settings = load_settings()
	suspects = set(load_suspects())

	off_start = parse_time(settings["off_hours"]["start"])
	off_end = parse_time(settings["off_hours"]["end"])

	# Etapa 1: Parsear y validar cada línea del log.
	parsed = []
	invalid = []

	# Contexto temporal para asociar eventos sin user explícito.
	current_user = None

	for index, line in enumerate(log_lines, start=1):
		item = parse_log_line(line)
		if not item["is_valid"]:
			invalid.append(
				{
					"linea": index,
					"error": item.get("error", "Error de validación"),
					"raw": item.get("raw", line),
				}
			)
			continue

		if item["event"] == "LOGIN" and item.get("user"):
			current_user = item["user"]

		item["effective_user"] = item.get("user") or current_user
		parsed.append(item)

	parsed.sort(key=lambda x: x["timestamp"])

	# Ejercicio 1: Parser de logs (fecha, evento, detalle).
	parser_output = [
		{
			"fecha": e["timestamp_str"],
			"evento": e["event"],
			"detalle": e["detail_text"],
		}
		for e in parsed
	]

	# Ejercicio 2: Detección de eventos críticos (DELETE y EXPORT).
	critical_events = [
		{
			"fecha": e["timestamp_str"],
			"evento": e["event"],
			"detalle": e["detail_text"],
			"usuario": e.get("effective_user"),
			"raw": e["raw"],
		}
		for e in parsed
		if e["event"] in CRITICAL_EVENTS
	]

	# Ejercicio 3: Detección de accesos de usuarios sospechosos (lista fija JSON).
	suspicious_events = []
	for e in parsed:
		# Se evalúa solo el usuario explícito de la línea para respetar el criterio original de la tarea.
		user = (e.get("user") or "").strip().lower()
		if user and user in suspects:
			suspicious_events.append(
				{
					"fecha": e["timestamp_str"],
					"evento": e["event"],
					"usuario": e.get("effective_user"),
					"detalle": e["detail_text"],
					"raw": e["raw"],
				}
			)

	# Ejercicio 4: Detección de actividad fuera del rango horario configurado.
	offhours_events = [
		{
			"fecha": e["timestamp_str"],
			"evento": e["event"],
			"usuario": e.get("effective_user"),
			"detalle": e["detail_text"],
			"raw": e["raw"],
		}
		for e in parsed
		if is_time_in_range(e["timestamp"].time(), off_start, off_end)
	]

	# Resumen de soporte para dashboard.
	by_event = Counter(e["event"] for e in parsed)
	timeline = Counter(e["timestamp"].strftime("%Y-%m-%d %H:00") for e in parsed)

	# Respuestas requeridas por la tarea — derivadas dinámicamente de los datos.
	deletes = [e for e in parsed if e["event"] == "DELETE"]
	exports = [e for e in parsed if e["event"] == "EXPORT"]
	has_delete = bool(deletes)
	has_export = bool(exports)

	susp_usernames = {(e.get("usuario") or "").strip().lower() for e in suspicious_events if e.get("usuario")}
	offhours_timestamps = {e["fecha"] for e in offhours_events}

	def _pl(n, singular, plural):
		return singular if n == 1 else plural

	# Q1
	if has_delete:
		most_critical_event = "DELETE"
		sample = deletes[0]
		who = sample.get("effective_user") or sample.get("user") or "desconocido"
		target = sample.get("detail_text", "")
		when = sample["timestamp"].strftime("%H:%M")
		is_offhours = sample["timestamp_str"] in offhours_timestamps
		is_susp = who.strip().lower() in susp_usernames
		n = len(deletes)
		partes = [f"DELETE es el evento más crítico de este registro."]
		if n == 1:
			partes.append(f"{who} eliminó {target} a las {when}.")
		else:
			partes.append(f"Se registraron {n} eliminaciones; la primera fue {target} por {who} a las {when}.")
		if is_susp:
			partes.append(f"{who} está clasificado como usuario sospechoso.")
		if is_offhours:
			partes.append(f"La acción ocurrió fuera del horario operativo.")
		partes.append(f"La eliminación destruye el dato de forma definitiva e irreversible, comprometiendo la integridad y disponibilidad del sistema.")
		critical_reason = " ".join(partes)
	elif has_export:
		most_critical_event = "EXPORT"
		sample = exports[0]
		who = sample.get("effective_user") or sample.get("user") or "desconocido"
		target = sample.get("detail_text", "")
		n = len(exports)
		if n == 1:
			critical_reason = (
				f"EXPORT es el evento más crítico registrado. "
				f"{who} exportó {target}, extrayendo datos fuera del sistema. "
				f"La confidencialidad quedó comprometida desde el momento de la extracción."
			)
		else:
			critical_reason = (
				f"EXPORT es el evento más crítico registrado. "
				f"Se realizaron {n} exportaciones; la primera fue {target} por {who}. "
				f"La confidencialidad quedó comprometida desde el momento de la extracción."
			)
	else:
		most_critical_event = "N/A"
		critical_reason = "Los logs analizados no contienen eventos DELETE ni EXPORT."

	# Q2
	riesgo_partes = []
	if has_export:
		exp = exports[0]
		exp_who = exp.get("effective_user") or exp.get("user") or "desconocido"
		exp_target = exp.get("detail_text", "")
		riesgo_partes.append(
			f"La exportación de {exp_target} realizada por {exp_who} comprometió la confidencialidad: "
			f"los datos salieron del sistema y pueden estar en manos no autorizadas."
		)
	if has_delete:
		d = deletes[0]
		del_who = d.get("effective_user") or d.get("user") or "desconocido"
		del_target = d.get("detail_text", "")
		riesgo_partes.append(
			f"La eliminación de {del_target} realizada por {del_who} comprometió la integridad y disponibilidad: "
			f"el dato fue destruido de forma definitiva."
		)
	if not riesgo_partes:
		riesgo_partes.append("Los logs analizados no contienen eventos EXPORT ni DELETE.")
	riesgo_export_delete = " ".join(riesgo_partes)

	# Q3
	criticos_por_susp = [
		e for e in critical_events
		if (e.get("usuario") or "").strip().lower() in susp_usernames
	]
	partes_q3 = []
	if criticos_por_susp:
		u = criticos_por_susp[0].get("usuario", "")
		ev = criticos_por_susp[0].get("evento", "")
		det = criticos_por_susp[0].get("detalle", "")
		partes_q3.append(
			f"Falló el control de mínimo privilegio: {u} ejecutó {ev} sobre {det} sin que el sistema aplicara restricción."
		)
	elif suspicious_events:
		u = suspicious_events[0].get("usuario", "")
		partes_q3.append(
			f"Falló el control de mínimo privilegio: {u} accedió al sistema sin restricción de acceso."
		)
	if offhours_events:
		n_off = len(offhours_events)
		start_h = settings["off_hours"]["start"]
		end_h = settings["off_hours"]["end"]
		partes_q3.append(
			f"Falló el control de monitoreo fuera de horario: "
			f"{n_off} {_pl(n_off, 'evento ocurrió', 'eventos ocurrieron')} "
			f"entre las {start_h} y las {end_h} sin bloqueo ni alerta."
		)
	if critical_events and not criticos_por_susp:
		n_crit = len(critical_events)
		partes_q3.append(
			f"Falló el control de autorización: "
			f"{n_crit} {_pl(n_crit, 'operación crítica fue ejecutada', 'operaciones críticas fueron ejecutadas')} "
			f"sin aprobación previa registrada."
		)
	if not partes_q3:
		partes_q3.append("Los logs analizados no presentan violaciones de controles de gobierno.")
	control_gobierno_fallo = " ".join(partes_q3)

	qa_answers = {
		"evento_mas_critico": {
			"evento": most_critical_event,
			"porque": critical_reason,
		},
		"riesgo_export_delete": riesgo_export_delete,
		"control_gobierno_fallo": control_gobierno_fallo,
	}

	# Salida estructurada para UI y reporte académico.
	return {
		"meta": {
			"processed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
			"total_lines": len(log_lines),
			"valid_lines": len(parsed),
			"invalid_lines": len(invalid),
			"off_hours_config": settings["off_hours"],
		},
		"kpis": {
			"total_events": len(parsed),
			"critical_events": len(critical_events),
			"suspicious_events": len(suspicious_events),
			"offhours_events": len(offhours_events),
		},
		"analysis_1_parser": parser_output,
		"analysis_2_critical": critical_events,
		"analysis_3_suspicious": suspicious_events,
		"analysis_4_offhours": offhours_events,
		"breakdown": {
			"events_by_type": dict(by_event),
			"timeline_by_hour": dict(sorted(timeline.items())),
		},
		"qa_answers": qa_answers,
		"invalid_lines": invalid,
		"validation": {
			"has_errors": len(invalid) > 0,
			"error_count": len(invalid),
		},
	}


class RequestHandler(BaseHTTPRequestHandler):
	def _send_json(self, payload: dict, status: int = 200) -> None:
		body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
		self.send_response(status)
		self.send_header("Content-Type", "application/json; charset=utf-8")
		self.send_header("Content-Length", str(len(body)))
		self.end_headers()
		self.wfile.write(body)

	def _send_html(self, html: str, status: int = 200) -> None:
		body = html.encode("utf-8")
		self.send_response(status)
		self.send_header("Content-Type", "text/html; charset=utf-8")
		self.send_header("Content-Length", str(len(body)))
		self.end_headers()
		self.wfile.write(body)

	def _read_json_body(self) -> dict:
		length = int(self.headers.get("Content-Length", "0"))
		raw = self.rfile.read(length) if length > 0 else b"{}"
		try:
			return json.loads(raw.decode("utf-8"))
		except json.JSONDecodeError:
			return {}

	def do_GET(self):
		parsed = urlparse(self.path)
		route = parsed.path

		if route == "/":
			if not PORTAL_PATH.exists():
				self._send_html("<h1>portal.html no encontrado</h1>", status=404)
				return
			self._send_html(PORTAL_PATH.read_text(encoding="utf-8"))
			return

		if route == "/api/config":
			self._send_json(load_settings())
			return

		if route == "/api/suspects":
			self._send_json({"users": load_suspects()})
			return

		if route == "/api/sample":
			if not SAMPLE_LOGS_PATH.exists():
				self._send_json({"error": "logs_input.txt no existe"}, status=404)
				return
			lines = SAMPLE_LOGS_PATH.read_text(encoding="utf-8").splitlines()
			self._send_json({"logs_text": "\n".join(lines)})
			return

		self._send_json({"error": "Ruta no encontrada"}, status=404)

	def do_PUT(self):
		parsed = urlparse(self.path)
		route = parsed.path

		if route == "/api/config":
			body = self._read_json_body()
			start = str(body.get("start", "")).strip()
			end = str(body.get("end", "")).strip()

			ok, message = validate_time_range(start, end)
			if not ok:
				self._send_json({"error": message}, status=400)
				return

			payload = {"off_hours": {"start": start, "end": end}}
			save_json(SETTINGS_PATH, payload)
			self._send_json(payload)
			return

		if route == "/api/suspects":
			body = self._read_json_body()
			users = body.get("users", [])
			if not isinstance(users, list):
				self._send_json({"error": "Formato inválido. users debe ser lista."}, status=400)
				return

			normalized = normalize_suspects(users)
			save_suspects(normalized)
			self._send_json({"users": normalized})
			return

		if route not in {"/api/config", "/api/suspects"}:
			self._send_json({"error": "Ruta no encontrada"}, status=404)
			return

	def do_POST(self):
		parsed = urlparse(self.path)
		route = parsed.path

		if route == "/api/suspects":
			body = self._read_json_body()
			users = body.get("users", [])
			if not isinstance(users, list):
				self._send_json({"error": "Formato inválido. users debe ser lista."}, status=400)
				return

			normalized = normalize_suspects(users)
			save_suspects(normalized)
			self._send_json({"users": normalized})
			return

		if route != "/api/analyze":
			self._send_json({"error": "Ruta no encontrada"}, status=404)
			return

		body = self._read_json_body()
		logs_text = body.get("logs_text")

		if not logs_text:
			if SAMPLE_LOGS_PATH.exists():
				logs_text = SAMPLE_LOGS_PATH.read_text(encoding="utf-8")
			else:
				self._send_json({"error": "No se enviaron logs y no existe sample"}, status=400)
				return

		# Retardo controlado para exponer barra de progreso en frontend.
		time_module.sleep(2.5)

		lines = str(logs_text).splitlines()
		result = analyze_logs(lines)
		self._send_json(result)


def run() -> None:
	ensure_data_files()
	host = "0.0.0.0"
	port = int(os.getenv("PORT", "8000"))
	server = HTTPServer((host, port), RequestHandler)
	print(f"Servidor listo en http://{host}:{port}")
	server.serve_forever()


if __name__ == "__main__":
	run()

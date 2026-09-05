# M5.5 — Safe HTTP Method Strategy

Observation planning defaults to HEAD when response body evidence is not required. GET is selected only when body evidence is explicitly required. Authorization and permits are still evaluated for the exact selected method.

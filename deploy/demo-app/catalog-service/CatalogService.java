import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Java catalog-service for cross-language tracing demo.
 * Uses JDK built-in HttpServer - zero external dependencies.
 * Calls .NET pricing-service for price enrichment.
 */
public class CatalogService {

    static final int PORT = Integer.parseInt(System.getenv().getOrDefault("PORT", "8081"));
    static final String PRICING_SERVICE_URL = System.getenv().getOrDefault("PRICING_SERVICE_URL", "http://localhost:8082");

    // In-memory product catalog (matches MySQL inventory SKUs)
    static final Map<String, Map<String, String>> CATALOG = new LinkedHashMap<>();
    static {
        CATALOG.put("WDG-001", Map.of("sku", "WDG-001", "name", "Premium Widget", "category", "widgets", "description", "High-quality premium widget"));
        CATALOG.put("GDG-001", Map.of("sku", "GDG-001", "name", "Standard Gadget", "category", "gadgets", "description", "Reliable standard gadget"));
        CATALOG.put("SPR-001", Map.of("sku", "SPR-001", "name", "Super Sprocket", "category", "sprockets", "description", "Industrial-grade sprocket"));
        CATALOG.put("GZM-001", Map.of("sku", "GZM-001", "name", "Mega Gizmo", "category", "gizmos", "description", "Feature-packed mega gizmo"));
        CATALOG.put("DHK-001", Map.of("sku", "DHK-001", "name", "Doohickey Pro", "category", "doohickeys", "description", "Professional doohickey"));
    }

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        server.createContext("/api/health", new HealthHandler());
        server.createContext("/api/catalog", new CatalogHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("catalog-service started on port " + PORT);
    }

    static class HealthHandler implements HttpHandler {
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }
            String response = "{\"status\":\"ok\",\"service\":\"catalog-service\"}";
            sendJson(exchange, 200, response);
        }
    }

    static class CatalogHandler implements HttpHandler {
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            String path = exchange.getRequestURI().getPath();

            if (path.equals("/api/catalog")) {
                // List all products
                StringBuilder sb = new StringBuilder("[");
                boolean first = true;
                for (Map<String, String> product : CATALOG.values()) {
                    if (!first) sb.append(",");
                    sb.append(productToJson(product));
                    first = false;
                }
                sb.append("]");
                sendJson(exchange, 200, sb.toString());
                return;
            }

            // Extract SKU from /api/catalog/{sku}
            String sku = path.substring("/api/catalog/".length()).toUpperCase();
            Map<String, String> product = CATALOG.get(sku);
            if (product == null) {
                sendJson(exchange, 404, "{\"error\":\"product not found\",\"sku\":\"" + sku + "\"}");
                return;
            }

            // Call pricing-service for price enrichment
            String pricing = fetchPricing(sku);

            String response = "{\"sku\":\"" + esc(product.get("sku")) + "\""
                    + ",\"name\":\"" + esc(product.get("name")) + "\""
                    + ",\"category\":\"" + esc(product.get("category")) + "\""
                    + ",\"description\":\"" + esc(product.get("description")) + "\""
                    + ",\"pricing\":" + pricing + "}";
            sendJson(exchange, 200, response);
        }
    }

    static String fetchPricing(String sku) {
        try {
            URL url = new URL(PRICING_SERVICE_URL + "/api/pricing/" + sku);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);

            int status = conn.getResponseCode();
            if (status == 200) {
                return readStream(conn.getInputStream());
            }
            return "{\"error\":\"pricing unavailable\",\"status\":" + status + "}";
        } catch (Exception e) {
            return "{\"error\":\"pricing-service unreachable\",\"detail\":\"" + esc(e.getMessage()) + "\"}";
        }
    }

    static String readStream(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[1024];
        int n;
        while ((n = in.read(buf)) != -1) {
            out.write(buf, 0, n);
        }
        return out.toString(StandardCharsets.UTF_8.name());
    }

    static String productToJson(Map<String, String> p) {
        return "{\"sku\":\"" + esc(p.get("sku")) + "\""
                + ",\"name\":\"" + esc(p.get("name")) + "\""
                + ",\"category\":\"" + esc(p.get("category")) + "\""
                + ",\"description\":\"" + esc(p.get("description")) + "\"}";
    }

    static void sendJson(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        OutputStream os = exchange.getResponseBody();
        os.write(bytes);
        os.close();
    }

    static String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}

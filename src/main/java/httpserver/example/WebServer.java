package httpserver.example;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

public class WebServer {

    private static final InetSocketAddress SERVER_API_ADDRESS = new InetSocketAddress("0.0.0.0", 80);
    private static final String HTTP_REQUEST_ALLOWED_ADDRESS = "ip";
    private static final String HTTP_REQUEST_ALLOWED_PASSWORD = "password";

    HttpServer server;
    ThreadPoolExecutor threadPoolExecutor = (ThreadPoolExecutor) Executors.newFixedThreadPool(1);

    {

        try {
            server = HttpServer.create(SERVER_API_ADDRESS, 0);
            server.createContext("/statistics", new httpRequestHandler());
            server.setExecutor(threadPoolExecutor);
            server.start();
            System.out.println("Server running at " + SERVER_API_ADDRESS);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    class httpRequestHandler implements HttpHandler {

         @Override
         public void handle(HttpExchange exchange) throws IOException {

             if (!isHttpRequestValid(exchange)) {
                 redirectForbiddenPage(exchange);
             } else {
                 sendResponse(exchange);
             }
         }

        private void sendResponse(HttpExchange exchange) throws IOException {

            OutputStream os = exchange.getResponseBody();
            StringBuilder htmlBuilder = new StringBuilder();

            htmlBuilder.append("<html>\n");
            htmlBuilder.append("<head>\n");
            htmlBuilder.append("</head>\n");
            htmlBuilder.append("<body>\n");
            htmlBuilder.append("<h1>Request Verified - this is response.</h1>\n");
            htmlBuilder.append("</body>\n");
            htmlBuilder.append("</html>\n");
            exchange.getResponseHeaders().set("Content-type", "charset=UTF-8");
            ByteBuffer buffer = StandardCharsets.UTF_8.encode(htmlBuilder.toString());
            byte[] bytes = new byte[buffer.remaining()];
            buffer.get(bytes);
            exchange.sendResponseHeaders(200, bytes.length);
            os.write(bytes);
            os.flush();
            os.close();
        }

        private void redirectForbiddenPage(HttpExchange exchange) throws IOException {

            OutputStream os = exchange.getResponseBody();
            StringBuilder htmlBuilder = new StringBuilder();

            htmlBuilder.append("<html>\n");
            htmlBuilder.append("<head>\n");
            htmlBuilder.append("</head>\n");
            htmlBuilder.append("<body>\n");
            htmlBuilder.append("You are not authorized" +"\n");
            htmlBuilder.append("</body>\n");
            htmlBuilder.append("</html>\n");
            exchange.getResponseHeaders().set("Content-type", "charset=UTF-8");
            ByteBuffer buffer = StandardCharsets.UTF_8.encode(htmlBuilder.toString());
            byte[] bytes = new byte[buffer.remaining()];
            buffer.get(bytes);
            exchange.sendResponseHeaders(403, bytes.length);
            os.write(bytes);
            os.flush();
            os.close();
        }

    }

    /**
     * Private method used to validate incoming http request
     * @param  exchange used to extract required attributes:
     * method type, password and remote address
     * @return boolean
     */
    private boolean isHttpRequestValid(HttpExchange exchange){

        if (!exchange.getRequestMethod().equals("POST"))
            return false;

        String httpRequestAddress = exchange.getRemoteAddress().getAddress().getHostAddress();
        Headers attributes = exchange.getRequestHeaders();

        String httpRequestPassword;
        if (attributes.containsKey("password"))
            httpRequestPassword = (String) attributes.get("password").get(0);
        else
            return false;

        return httpRequestPassword.equals(HTTP_REQUEST_ALLOWED_PASSWORD) && httpRequestAddress.equals(HTTP_REQUEST_ALLOWED_ADDRESS);
    }
}

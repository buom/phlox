package me.buom.phlox;

import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.server.handler.HandlerCollection;
import org.eclipse.jetty.util.thread.QueuedThreadPool;

import static com.google.common.base.Strings.isNullOrEmpty;

public class PhloxServer {
    static final String SECRET = System.getenv("PHLOX_SECRET");
    static final String SALT = System.getenv("PHLOX_SALT");

    public void start() throws Exception {
        int maxThreads = Integer.parseInt(System.getProperty("maxThreads", "200"));
        int minThreads = Integer.parseInt(System.getProperty("minThreads", "8"));
        int idleTimeout = Integer.parseInt(System.getProperty("idleTimeout", "60000"));

        QueuedThreadPool threadPool = new QueuedThreadPool(maxThreads, minThreads, idleTimeout);
        Server server = new Server(threadPool);
        HttpConfiguration conf = new HttpConfiguration();
        conf.setSendServerVersion(false);
        HttpConnectionFactory factory = new HttpConnectionFactory(conf);
        ServerConnector connector = new ServerConnector(server, factory);

        int port = Integer.parseInt(System.getProperty("port", "8090"));
        connector.setPort(port);

        server.setConnectors(new Connector[]{connector});

        HandlerCollection collection = new HandlerCollection();

        ContextHandler context = new ContextHandler("/");
        context.setHandler(new PhloxServerHandler());
        collection.addHandler(context);

        server.setHandler(collection);

        server.start();
        server.join();
    }

    public static void main(String[] args) throws Exception {
        if (!isNullOrEmpty(SECRET) & !isNullOrEmpty(SALT)) {
            new PhloxServer().start();
        } else {
            String text = String.format("\n%s\n\t%s\n\t%s\n\t%s\n%s",
                    "Usage:",
                    "export PHLOX_SECRET=...",
                    "export PHLOX_SALT=...",
                    "./bin/phlox",
                    "Enjoy ^^");
            System.err.println(text);
        }
    }
}

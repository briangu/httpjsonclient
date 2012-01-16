package httpjsonclient;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.io.IOUtils;
import org.apache.http.Header;
import org.apache.http.HeaderElement;
import org.apache.http.HeaderElementIterator;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.HttpResponse;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.NameValuePair;
import org.apache.http.NoHttpResponseException;
import org.apache.http.client.HttpRequestRetryHandler;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.utils.URIUtils;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.scheme.SchemeSocketFactory;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.entity.HttpEntityWrapper;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultConnectionKeepAliveStrategy;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.message.BasicHeaderElementIterator;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.CoreConnectionPNames;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.ExecutionContext;
import org.apache.http.protocol.HTTP;
import org.apache.http.protocol.HttpContext;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;


public class HttpJSONClient
{
  String _scheme;
  String _host;
  int _port;
  String _path;
  int _defaultKeepAliveDurationMS;
  int _maxRetries;
  DefaultHttpClient _httpclient;
  TrustManager _trustManager;

  public static class JSONRequestResponse
  {
    public final int StatusCode;
    public final JSONObject JsonResult;
    public final HttpResponse HttpResponse;

    public JSONRequestResponse(JSONObject obj, HttpResponse response)
    {
      StatusCode = response.getStatusLine().getStatusCode();
      JsonResult = obj;
      HttpResponse = response;
    }
  }

  public static HttpJSONClient create(String url)
      throws IOException, NoSuchAlgorithmException, KeyManagementException
  {
    URL urlObj = new URL(url);

    return new HttpJSONClient(
      urlObj.getProtocol(),
      urlObj.getHost(),
      urlObj.getPort(),
      urlObj.getPath());
  }

  public HttpJSONClient(String scheme, String host, int port, String path)
    throws NoSuchAlgorithmException, IOException, KeyManagementException
  {
    this(
      scheme,
      host,
      port,
      path,
      5000,
      5);
  }

  public HttpJSONClient(String scheme,
                        String host,
                        int port,
                        String path,
                        int defaultKeepAliveDurationMS,
                        final int maxRetries)
    throws NoSuchAlgorithmException, IOException, KeyManagementException
  {
    this(scheme,
         host,
         port,
         path,
         defaultKeepAliveDurationMS,
         maxRetries,
         new X509TrustManager() {

           @Override
           public void checkClientTrusted(java.security.cert.X509Certificate[] x509Certificates, String s)
             throws java.security.cert.CertificateException
           {
           }

           @Override
           public void checkServerTrusted(java.security.cert.X509Certificate[] x509Certificates, String s)
             throws java.security.cert.CertificateException
           {
           }

           @Override
           public java.security.cert.X509Certificate[] getAcceptedIssuers()
           {
             return new java.security.cert.X509Certificate[0];
           }
         },
         null);
  }

  public HttpJSONClient(String scheme,
                        String host,
                        int port,
                        String path,
                        int defaultKeepAliveDurationMS,
                        final int maxRetries,
                        TrustManager trustManager,
                        HttpRequestRetryHandler retryHandler)
    throws NoSuchAlgorithmException, IOException, KeyManagementException
  {
    _scheme = scheme;
    _host = host;
    _port = port;
    _path = path;
    _defaultKeepAliveDurationMS = defaultKeepAliveDurationMS;
    _maxRetries = maxRetries;
    _trustManager = trustManager;
    _httpclient = createHttpClient(retryHandler);
  }

  private DefaultHttpClient createHttpClient(HttpRequestRetryHandler retryHandler)
    throws NoSuchAlgorithmException, KeyManagementException, IOException
  {
    HttpParams params = new BasicHttpParams();
    params.setParameter(CoreConnectionPNames.CONNECTION_TIMEOUT, 30000);

    SchemeRegistry registry = new SchemeRegistry();
    SchemeSocketFactory sf;

    if (_scheme.equals("https"))
    {
      SSLContext sslcontext = SSLContext.getInstance("TLS");
      sslcontext.init(null, new TrustManager[] { _trustManager }, null);
      sf = new SSLSocketFactory(sslcontext);
    }
    else
    {
      sf = PlainSocketFactory.getSocketFactory();
    }

    registry.register(new Scheme(_scheme, _port, sf));

    ClientConnectionManager cm = new ThreadSafeClientConnManager(registry);
    DefaultHttpClient client = new DefaultHttpClient(cm, params);
    if (retryHandler == null)
    {
      retryHandler = new HttpRequestRetryHandler()
      {
        public boolean retryRequest(IOException exception, int executionCount, HttpContext context)
        {
          if (executionCount >= _maxRetries)
          {
            // Do not retry if over max retry count
            return false;
          }
          if (exception instanceof NoHttpResponseException)
          {
            // Retry if the server dropped connection on us
            return true;
          }
          if (exception instanceof SSLHandshakeException)
          {
            // Do not retry on SSL handshake exception
            return false;
          }
          HttpRequest request = (HttpRequest) context.getAttribute(ExecutionContext.HTTP_REQUEST);
          boolean idempotent = !(request instanceof HttpEntityEnclosingRequest);
          if (idempotent)
          {
            // Retry if the request is considered idempotent
            return true;
          }
          return false;
        }
      };
    }
    client.setHttpRequestRetryHandler(retryHandler);

    client.addRequestInterceptor(new HttpRequestInterceptor()
    {
      public void process(final HttpRequest request, final HttpContext context)
        throws HttpException, IOException
      {
        if (!request.containsHeader("Accept-Encoding"))
        {
          request.addHeader("Accept-Encoding", "gzip");
        }
      }
    });

    client.addResponseInterceptor(new HttpResponseInterceptor()
    {
      public void process(final HttpResponse response, final HttpContext context)
        throws HttpException, IOException
      {
        HttpEntity entity = response.getEntity();
        if (entity != null)
        {
          Header ceheader = entity.getContentEncoding();
          if (ceheader != null)
          {
            HeaderElement[] codecs = ceheader.getElements();
            for (int i = 0; i < codecs.length; i++)
            {
              if (codecs[i].getName().equalsIgnoreCase("gzip"))
              {
                response.setEntity(new GzipDecompressingEntity(response.getEntity()));
                return;
              }
            }
          }
        }
      }
    });

    client.setKeepAliveStrategy(new DefaultConnectionKeepAliveStrategy()
    {
      @Override
      public long getKeepAliveDuration(HttpResponse response, HttpContext context)
      {
        // Honor 'keep-alive' header
        HeaderElementIterator it = new BasicHeaderElementIterator(response.headerIterator(HTTP.CONN_KEEP_ALIVE));
        while (it.hasNext())
        {
          HeaderElement he = it.nextElement();
          String param = he.getName();
          String value = he.getValue();
          if ((value != null) && param.equalsIgnoreCase("timeout"))
          {
            try
            {
              return Long.parseLong(value) * 1000;
            }
            catch (NumberFormatException ignore)
            {
            }
          }
        }

        long keepAlive = super.getKeepAliveDuration(response, context);
        if (keepAlive == -1)
        {
          keepAlive = _defaultKeepAliveDurationMS;
        }
        return keepAlive;
      }
    });

    return client;
  }

  private static class GzipDecompressingEntity extends HttpEntityWrapper
  {
    public GzipDecompressingEntity(final HttpEntity entity)
    {
      super(entity);
    }

    @Override
    public InputStream getContent()
      throws IOException, IllegalStateException
    {
      // the wrapped entity's getContent() decides about repeatability
      InputStream wrappedin = wrappedEntity.getContent();
      return new GZIPInputStream(wrappedin);
    }

    @Override
    public long getContentLength()
    {
      // length of ungzipped content is not known
      return -1;
    }

  }

  public JSONRequestResponse doQuery()
    throws URISyntaxException, IOException, JSONException
  {
    return doQuery(Collections.<NameValuePair>emptyList());
  }

  public JSONRequestResponse doQuery(List<NameValuePair> queryParams)
    throws URISyntaxException, IOException, JSONException
  {
    URI requestURI = buildRequestURI(queryParams);
    HttpResponse response = makeGetRequest(requestURI);
    JSONObject result = transformResponseToJSONObject(response);
    return new JSONRequestResponse(result, response);
  }

  // POST actions
  public JSONRequestResponse doPost(List<NameValuePair> nameValuePairs)
    throws URISyntaxException, IOException, JSONException
  {
    return doPost(nameValuePairs, Collections.<NameValuePair>emptyList(), Collections.<String, String>emptyMap());
  }

  public JSONRequestResponse doPost(List<NameValuePair> nameValuePairs, List<NameValuePair> queryParams)
    throws URISyntaxException, IOException, JSONException
  {
    return doPost(nameValuePairs, queryParams, Collections.<String, String>emptyMap());
  }

  public JSONRequestResponse doPost(List<NameValuePair> nameValuePairs, Map<String,String> headers)
    throws URISyntaxException, IOException, JSONException
  {
    return doPost(nameValuePairs, Collections.<NameValuePair>emptyList(), headers);
  }

  public JSONRequestResponse doPost(List<NameValuePair> nameValuePairs, List<NameValuePair> queryParams, Map<String,String> headers)
    throws URISyntaxException, IOException, JSONException
  {
    JSONRequestResponse jsonResponse;
    InputStream is = null;

    try
    {
      URI requestURI = buildRequestURI(queryParams);
      HttpResponse response = makePostRequest(requestURI, nameValuePairs, headers);
      is = response.getEntity().getContent();
      jsonResponse = new JSONRequestResponse(transformResponseToJSONObject(response), response);
    }
    finally
    {
      if (is != null)
      {
    	  IOUtils.closeQuietly(is);
      }
    }

    return jsonResponse;
  }

  // DELETE actions
  public JSONRequestResponse doDelete()
      throws URISyntaxException, IOException, JSONException
  {
    return doDelete(Collections.<String, String>emptyMap());
  }

  private JSONRequestResponse doDelete(Map<String, String> headers)
      throws IOException, URISyntaxException, JSONException
  {
    return doDelete(headers, Collections.<NameValuePair>emptyList());
  }

  public JSONRequestResponse doDelete(Map<String,String> headers, List<NameValuePair> queryParams)
    throws URISyntaxException, IOException, JSONException
  {
    URI requestURI = buildRequestURI(queryParams);
    HttpResponse response = makeDeleteRequest(requestURI, headers);
    JSONObject result = transformResponseToJSONObject(response);

    return new JSONRequestResponse(result, response);
  }

  private HttpResponse makeDeleteRequest(URI uri, Map<String,String> headers)
    throws IOException
  {
    HttpDelete request = new HttpDelete(uri);
    return makeHttpRequest(request, headers);
  }


  // PUT actions
  public JSONRequestResponse doPut(JSONObject obj)
    throws URISyntaxException, IOException, JSONException
  {
    return doPut(obj.toString(), Collections.<String, String>emptyMap());
  }

  public JSONRequestResponse doPut(String data)
    throws URISyntaxException, IOException, JSONException
  {
    return doPut(data, Collections.<String, String>emptyMap());
  }

  public JSONRequestResponse doPut(String data, Map<String,String> headers)
    throws URISyntaxException, IOException, JSONException
  {
    return doPut(data, headers, Collections.<NameValuePair>emptyList());
  }

  public JSONRequestResponse doPut(String data, Map<String,String> headers, List<NameValuePair> queryParams)
    throws URISyntaxException, IOException, JSONException
  {
    URI requestURI = buildRequestURI(queryParams);
    HttpResponse response = makePutRequest(requestURI, data, headers);
    JSONObject result = transformResponseToJSONObject(response);
    
    return new JSONRequestResponse(result, response);
  }

/*
  public JSONObject doPut(List<NameValuePair> nameValuePairs)
    throws URISyntaxException, IOException, JSONException
  {
    return doPut(nameValuePairs, Collections.<NameValuePair>emptyList(), Collections.<String, String>emptyMap());
  }

  public JSONObject doPut(List<NameValuePair> nameValuePairs, List<NameValuePair> queryParams)
    throws URISyntaxException, IOException, JSONException
  {
    return doPut(nameValuePairs, queryParams, Collections.<String, String>emptyMap());
  }

  public JSONObject doPut(List<NameValuePair> nameValuePairs, Map<String,String> headers)
    throws URISyntaxException, IOException, JSONException
  {
    return doPut(nameValuePairs, Collections.<NameValuePair>emptyList(), headers);
  }

  public JSONObject doPut(List<NameValuePair> nameValuePairs, List<NameValuePair> queryParams, Map<String,String> headers)
    throws URISyntaxException, IOException, JSONException
  {
    JSONObject result;
    InputStream is = null;

    try
    {
      URI requestURI = buildRequestURI(queryParams);
      HttpResponse response = makePutRequest(requestURI, nameValuePairs, headers);
      is = response.getEntity().getContent();
      result = transformResponseToJSONObject(response);
    }
    finally
    {
      if (is != null)
      {
        IOUtils.closeQuietly(is);
      }
    }

    return result;
  }
*/

  public JSONRequestResponse doPost(JSONObject data)
    throws URISyntaxException, IOException, JSONException
  {
    return doPost(data.toString(2), Collections.<String, String>emptyMap());
  }

  public JSONRequestResponse doPost(JSONObject data, List<NameValuePair> queryParams)
    throws URISyntaxException, IOException, JSONException
  {
    return doPost(data.toString(2), Collections.<String, String>emptyMap(), queryParams);
  }

  public JSONRequestResponse doPost(String data)
    throws URISyntaxException, IOException, JSONException
  {
    return doPost(data, Collections.<String, String>emptyMap());
  }

  public JSONRequestResponse doPost(String data, Map<String,String> headers)
    throws URISyntaxException, IOException, JSONException
  {
    return doPost(data, headers, Collections.<NameValuePair>emptyList());
  }

  public JSONRequestResponse doPost(String data, Map<String,String> headers, List<NameValuePair> queryParams)
    throws URISyntaxException, IOException, JSONException
  {
    URI requestURI = buildRequestURI(queryParams);
    HttpResponse response = makePostRequest(requestURI, data, headers);
    return new JSONRequestResponse(transformResponseToJSONObject(response), response);
  }

  public URI buildRequestURI()
      throws URISyntaxException
  {
    return buildRequestURI(new ArrayList<NameValuePair>());
  }

  public URI buildRequestURI(List<NameValuePair> qparams)
      throws URISyntaxException
  {
    URI uri =
      URIUtils.createURI(
        _scheme,
        _host,
        _port,
        _path,
        URLEncodedUtils.format(qparams, "UTF-8"),
        null);
    return uri;
  }

  private HttpResponse makeGetRequest(URI uri)
      throws IOException
  {
    HttpGet httpget = new HttpGet(uri);
    HttpResponse response = _httpclient.execute(httpget);
    HttpEntity entity = response.getEntity();
    if (entity == null)
    {
      throw new IOException("failed to complete request");
    }

    return response;
  }

  // POST HELPERS
  private HttpResponse makePostRequest(URI uri, List<NameValuePair> nameValuePairs)
      throws IOException
  {
    return makePostRequest(uri, nameValuePairs, new HashMap<String, String>());
  }

  private HttpResponse makePostRequest(URI uri, List<NameValuePair> nameValuePairs, Map<String,String> headers)
      throws IOException
  {
    return makePostRequest(uri, new UrlEncodedFormEntity(nameValuePairs), headers);
  }

  private HttpResponse makePostRequest(URI uri, String data, Map<String,String> headers)
      throws IOException
  {
    StringEntity se = new StringEntity(data, HTTP.UTF_8);
    se.setContentEncoding("UTF-8");
    return makePostRequest(uri, se, headers);
  }

  private HttpResponse makePostRequest(URI uri, HttpEntity entity, Map<String,String> headers)
      throws IOException
  {
    HttpPost request = new HttpPost(uri);
    request.setEntity(entity);
    return makeHttpRequest(request, headers);
  }

  // PUT HELPERS

/*
  private HttpResponse makePutRequest(URI uri, List<NameValuePair> nameValuePairs)
    throws IOException
  {
    return makePutRequest(uri, nameValuePairs, new HashMap<String, String>());
  }

  private HttpResponse makePutRequest(URI uri, List<NameValuePair> nameValuePairs, Map<String,String> headers)
    throws IOException
  {
    return makePutRequest(uri, new UrlEncodedFormEntity(nameValuePairs), headers);
  }
*/
  private HttpResponse makePutRequest(URI uri, String data, Map<String,String> headers)
    throws IOException
  {
    StringEntity se = new StringEntity(data, HTTP.UTF_8);
    se.setContentEncoding("UTF-8");
    return makePutRequest(uri, se, headers);
  }

  private HttpResponse makePutRequest(URI uri, HttpEntity entity, Map<String,String> headers)
    throws IOException
  {
    HttpPut request = new HttpPut(uri);
    request.setEntity(entity);
    return makeHttpRequest(request, headers);
  }

  // COMMON REQUEST MAKER
  private HttpResponse makeHttpRequest(
    HttpRequestBase request,
    Map<String,String> headers)
      throws IOException
  {
    for (String key : headers.keySet())
    {
      request.setHeader(key, headers.get(key));
    }

    HttpResponse response = _httpclient.execute(request);
    int statusCode = response.getStatusLine().getStatusCode();
    if(statusCode == 400) {
      throw new IOException("Bad Request");
    }
    else if (statusCode == 204 || statusCode == 304)
    {
      // nothing
    }
    else
    {
      HttpEntity responseEntity = response.getEntity();
      if (responseEntity == null)
      {
        throw new IOException("failed to complete request");
      }
    }

    return response;
  }

  public static String join(String[] arr, String delimiter) {
    return join(Arrays.asList(arr), delimiter);
  }

  public static String join(Collection<?> s, String delimiter) {
    StringBuilder builder = new StringBuilder();
    Iterator iter = s.iterator();
    while (iter.hasNext()) {
       builder.append(iter.next().toString());
       if (!iter.hasNext()) {
         break;
       }
       builder.append(delimiter);
    }
    return builder.toString();
  }

  public static String convertStreamToString(InputStream is)
      throws IOException
  {
    BufferedReader reader = new BufferedReader(new InputStreamReader(is));
    StringBuilder sb = new StringBuilder();
    char[] buf = new char[1024];  //1k buffer
     try
    {
      int count;
      while((count = reader.read(buf)) > 0) {
    	  sb.append(buf, 0, count);
      }
    }
    finally
    {
      is.close();
    }

    String json = sb.toString();
    return json;
  }

  public static JSONObject transformResponseToJSONObject(HttpResponse response)
      throws IOException, JSONException
  {
    HttpEntity entity = response.getEntity();

    if (entity == null)
    {
      return new JSONObject();
    }

    JSONObject result;
    InputStream is = null;

    try
    {
      is = response.getEntity().getContent();

      String rawJSON = convertStreamToString(is).trim();
      if (rawJSON.length() == 0)
      {
        result = new JSONObject();
      }
      else
      {
        if (rawJSON.startsWith("["))
        {
          result = new JSONObject();
          result.put("elements", new JSONArray(rawJSON));
        }
        else if (rawJSON.startsWith("{"))
        {
          result = new JSONObject(rawJSON);
        }
        else
        {
          throw new RuntimeException("error: " + rawJSON);
        }
      }

      JSONObject metaResponse = new JSONObject();
      Iterator<Header> iter = response.headerIterator();
      while(iter.hasNext())
      {
        Header header = iter.next();
        if (!header.getName().startsWith("X-LinkedIn-")) continue;
        String name = header.getName().substring("X-LinkedIn-".length());
        metaResponse.put(name, header.getValue());
      }
      if (metaResponse.length() > 0)
      {
        result.put("meta", metaResponse);
      }
    }
    finally
    {
      if (is != null)
      {
    	  IOUtils.closeQuietly(is);
      }
    }

    return result;
  }

  public void shutdown() {
    if (_httpclient == null) return;
    _httpclient.getConnectionManager().shutdown();
    _httpclient = null;
  }
}

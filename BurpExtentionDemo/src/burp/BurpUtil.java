package burp;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.*;

public class BurpUtil {
    private List<String> cacheHeader = Arrays.asList("Etag", "If-None-Match", "Cache-Control", "Last-Modified", "If-Modified-Since", "Vary", "Pragma", "Expires", "X" +
            "-Cache", "X-Ser");
    private List<String> requestHeaderKeyBlackList = Arrays.asList("Cache-Control", "Host", "Content-Length", "Connection", "Pragma");
    private List<String> requestHeaderValueBlackList = Arrays.asList("0", "1");

    public Map<String, String> praseHeader(List<String> headers){
        Map<String, String> result = new HashMap<String, String>();
        for(int i=1; i < headers.size(); i++){
            String[] tmp = headers.get(i).split(":", 2);
            if (tmp.length == 2){
                String key = tmp[0].trim();
                String value = tmp[1].trim();
                if (key.contains("Cookie")) {
                    for (String cookie : value.split("; ")) {
                        result.put(cookie.trim().split("=",2)[0], cookie.trim().split("=",2)[1]);
                    }
                }else{
                    result.put(key, value);
                }
            }
        }
        return result;
    }

    public responseResult getCacheHeader(Map<String, String> headers, String response){
        responseResult result = new responseResult();
        List<String> params = new ArrayList<>();
        List<int[]> responseMarkers = new ArrayList<>();
        for (String headerName: headers.keySet()){
            try {
                int lastpos = response.indexOf(URLDecoder.decode(headerName, "UTF-8"), 0);
                if (cacheHeader.contains(URLDecoder.decode(headerName, "UTF-8")) && lastpos != -1) {
                    params.add(headerName);
                    responseMarkers.add(new int[]{lastpos, lastpos + headerName.length()});
                }
            }catch (UnsupportedEncodingException e){
                continue;
            }
        }
        result.setParams(params);
        result.setResponseMarkers(responseMarkers);
        return result;
    }

    public requestResponseResult getReflectHeader(Map.Entry<String, String> header, String request, String response){
        requestResponseResult result = new requestResponseResult();
        List<String> params = new ArrayList<>();
        List<int[]> requestMarkers = new ArrayList<>();
        List<int[]> responseMarkers = new ArrayList<>();
        if (!requestHeaderKeyBlackList.contains(header.getKey()) && !requestHeaderValueBlackList.contains(header.getValue())) {
            try {
                int requestlastpos = request.indexOf(header.getKey(), 0);
                int lastpos = 0;
                while (response.indexOf(URLDecoder.decode(header.getValue(), "UTF-8"), lastpos) != -1) {
                    lastpos = response.indexOf(header.getValue(), lastpos);

                    // Marking value in the response
                    responseMarkers.add(new int[]{lastpos, lastpos + header.getValue().length()});
                    lastpos += 1;
                }
                if (lastpos != 0) {
                    params.add(header.getKey());
                    // 防止匹配出错
                    requestlastpos = request.indexOf(header.getValue(), requestlastpos);
                    requestMarkers.add(new int[]{requestlastpos, requestlastpos + header.getValue().length()});
                }
            } catch (UnsupportedEncodingException e) {

            }
        }
        result.setParams(params);
        result.setRequestMarkers(requestMarkers);
        result.setResponseMarkers(responseMarkers);
        return result;
    }
}


class responseResult{
    List<String> params;
    List<int[]> responseMarkers;

    public void setParams(List<String> params) {
        this.params = params;
    }

    public void setResponseMarkers(List<int[]> responseMarkers) {
        this.responseMarkers = responseMarkers;
    }

    public List<String> getParams() {
        return params;
    }

    public List<int[]> getResponseMarkers() {
        return responseMarkers;
    }
}

class requestResponseResult{
    List<String> params;
    List<int[]> requestMarkers;
    List<int[]> responseMarkers;

    public List<String> getParams() {
        return params;
    }

    public void setParams(List<String> params) {
        this.params = params;
    }

    public List<int[]> getRequestMarkers() {
        return requestMarkers;
    }

    public void setRequestMarkers(List<int[]> requestMarkers) {
        this.requestMarkers = requestMarkers;
    }

    public List<int[]> getResponseMarkers() {
        return responseMarkers;
    }

    public void setResponseMarkers(List<int[]> responseMarkers) {
        this.responseMarkers = responseMarkers;
    }
}
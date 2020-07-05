package burp;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
// todo 改名 reflect header
public class BurpExtender implements IBurpExtender, IScannerCheck{
    private String extensionName = "burpExtenderDemo";
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private BurpUtil burpUtil;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks){
        this.callbacks = callbacks;
        callbacks.setExtensionName(extensionName);
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        burpUtil = new BurpUtil();
        callbacks.registerScannerCheck(this);
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse){
        List<IScanIssue> issues = new ArrayList<>();
        IRequestInfo IResquest = helpers.analyzeRequest(baseRequestResponse.getRequest());
        IResponseInfo IResponse = helpers.analyzeResponse(baseRequestResponse.getResponse());
        String SRequest = new String(baseRequestResponse.getRequest());
        String SResponse = new String(baseRequestResponse.getResponse());
        Map<String, String> responseHeaders = burpUtil.praseHeader(IResponse.getHeaders());
        Map<String, String> requestHeaders = burpUtil.praseHeader(IResquest.getHeaders());
        stdout.println(IResquest.getHeaders());
        // get cache header
        responseResult cacheHeaderResult = burpUtil.getCacheHeader(responseHeaders, SResponse);
        if (cacheHeaderResult.getParams().size() > 0){
            issues.add(
                    new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, cacheHeaderResult.getResponseMarkers()) },
                            "Cache header detected",
                            "The http response header contains cache control http header: " + cacheHeaderResult.getParams(),
                            "High",
                            "Tentative"));
        }
        // get reflect header
        for (Map.Entry<String, String> header: requestHeaders.entrySet()) {
            requestResponseResult reflectHeaderResult = burpUtil.getReflectHeader(header, SRequest, SResponse);
            if (reflectHeaderResult.getParams().size() > 0){
                issues.add(
                        new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, reflectHeaderResult.getRequestMarkers(), reflectHeaderResult.getResponseMarkers()) },
                                "Reflect header detected",
                                "The http header was reflected on response, try web cache poison: " + reflectHeaderResult.getParams(),
                                "High",
                                "Tentative"));
            }
        }
        return issues.isEmpty() ? null : issues;
    }

    @Override
    public  List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint){
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueDetail().equals(newIssue.getIssueDetail())){
            return -1;
        }
        return 0;
    }
}

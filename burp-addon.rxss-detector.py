from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from threading import Lock
from java.awt.event import MouseAdapter;

class CMouseListener(MouseAdapter):
    def __init__(self, extender):
        self._extender = extender

    def mouseReleased(self, event):
        if event.getButton() == 3:
            rowIndex = event.getSource().rowAtPoint(event.getPoint())
            logEvent = self._extender._log.get(rowIndex)._requestResponse
            useHttps = False
            if logEvent.getProtocol() == "https":
                useHttps = True
            self._extender._callbacks.sendToRepeater(logEvent.getHost(), logEvent.getPort(), useHttps, logEvent.getRequest(), None)
           


class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel):
    
    def	registerExtenderCallbacks(self, callbacks):
    
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Reflected XSS Detector")
        
        # create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._lock = Lock()
        
        # main split pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        # table of log entries
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        self._splitpane.setLeftComponent(scrollPane)

        logTable.addMouseListener( CMouseListener(self) )

        # tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Response", self._responseViewer.getComponent())
        tabs.addTab("Request", self._requestViewer.getComponent())
        self._splitpane.setRightComponent(tabs)
        
        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)
        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)
        
        return
        
    #
    # implement ITab
    #
    
    def getTabCaption(self):
        return "R-XSS Detector"
    
    def getUiComponent(self):
        return self._splitpane
        
    #
    # implement IHttpListener
    #
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
    
        if not messageIsRequest:
            # create a new log entry with the message details
            mi = self._callbacks.saveBuffersToTempFiles(messageInfo)
            tmp = self._helpers.analyzeRequest(messageInfo).getParameters()
            response = bytearray(mi.getResponse())
            self._lock.acquire()
            for p in tmp:
                if response.find(str(p.getValue())) > 0:
                    row = self._log.size()
                    headers = self._helpers.analyzeResponse(mi.getResponse()).getHeaders()
                    cc = ""
                    for h in headers:
                        if h.find("Content-Type:") == 0:
                            cc = h[14:].lower()
                    accepted_ccs = ['text/html', 'application/json', 'application/x-javascript']
                    if cc in accepted_ccs:
                        self._log.add( LogEntry(toolFlag, mi, self._helpers.analyzeRequest(messageInfo).getUrl(), p.getType(), p.getName(), p.getValue() ) )
                        self.fireTableRowsInserted(row, row)
            self._lock.release()

        return

    #
    # extend AbstractTableModel
    #
    
    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 4

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Tool"
        if columnIndex == 1:
            return "URL"
        if columnIndex == 2:
            return "Status"
        if columnIndex == 3:
            return "Params"
        return ""
    def getRowAt(self, rowIndex):
        return self._log.get(rowIndex)

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return self._callbacks.getToolName(logEntry._tool)
        if columnIndex == 1:
            return logEntry._url.toString()
        if columnIndex == 2:
            return logEntry._requestResponse.getStatusCode()   
        if columnIndex == 3:
            types = ['GET','POST','COOKIE']
            return str(logEntry._key)+" ("+types[logEntry._key_type]+") = "+logEntry._value
        return ""

    #
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #
    
    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

#
# extend JTable to handle cell selection
#
    
class Table(JTable):

    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
        return
    
    def changeSelection(self, row, col, toggle, extend):
    
        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        resp = logEntry._requestResponse
        self._extender._responseViewer.setMessage(resp.getResponse(), False)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        
        JTable.changeSelection(self, row, col, toggle, extend)
        return


#
# class to hold details of each log entry
#

class LogEntry:

    def __init__(self, tool, requestResponse, url, key_type, key, value):
        self._tool = tool
        self._requestResponse = requestResponse
        self._url = url
        self._key_type = key_type
        self._key = key
        self._value = value
        return
      
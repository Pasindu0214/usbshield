class USBDevice:
    def __init__(self, vendor_id, product_id, serial=None, manufacturer=None, product=None):
        """
        Initialize a USB device.
        
        Args:
            vendor_id: The vendor ID as a string (e.g., "1234")
            product_id: The product ID as a string (e.g., "5678")
            serial: The serial number (optional)
            manufacturer: The manufacturer name (optional)
            product: The product name (optional)
        """
        self.vendor_id = vendor_id
        self.product_id = product_id
        self.serial = serial
        self.manufacturer = manufacturer or "Unknown"
        self.product = product or "Unknown Device"
        
    def get_identifier(self):
        """
        Get a unique identifier for this device.
        
        Returns:
            str: A unique identifier
        """
        if self.serial:
            return f"{self.vendor_id}:{self.product_id}:{self.serial}"
        return f"{self.vendor_id}:{self.product_id}"
        
    def __str__(self):
        if self.manufacturer and self.product:
            return f"{self.manufacturer} {self.product} ({self.vendor_id}:{self.product_id})"
        return f"USB Device {self.vendor_id}:{self.product_id}"
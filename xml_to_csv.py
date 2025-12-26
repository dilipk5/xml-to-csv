import xml.etree.ElementTree as ET
import csv
import sys
from datetime import datetime

def parse_event_xml(xml_string):
    """
    Parse Windows Event Log XML and extract relevant fields.
    
    Args:
        xml_string: XML string containing Windows Event data
        
    Returns:
        Dictionary with parsed event data
    """
    # Parse XML
    root = ET.fromstring(xml_string)
    
    # Define namespace
    ns = {'evt': 'http://schemas.microsoft.com/win/2004/08/events/event'}
    
    # Extract System data
    system = root.find('evt:System', ns)
    time_created = system.find('evt:TimeCreated', ns).get('SystemTime')
    computer = system.find('evt:Computer', ns).text
    
    # Convert ISO timestamp to readable format
    eventdate = datetime.fromisoformat(time_created.replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S')
    
    # Extract EventData
    event_data = root.find('evt:EventData', ns)
    data_dict = {}
    
    for data in event_data.findall('evt:Data', ns):
        name = data.get('Name')
        value = data.text if data.text else ''
        data_dict[name] = value
    
    # Map to CSV format
    csv_data = {
        'eventdate': eventdate,
        'hostname': computer,
        'user': data_dict.get('SubjectUserName', ''),
        'processid': data_dict.get('NewProcessId', ''),
        'image': data_dict.get('NewProcessName', ''),
        'processcommandline': data_dict.get('CommandLine', ''),
        'hashes': ''  # Not present in Event ID 4688 by default
    }
    
    return csv_data

def xml_to_csv(xml_input_file, output_csv='output.csv'):
    """
    Convert Windows Event XML to CSV file.
    
    Args:
        xml_input_file: Path to XML file containing event data
        output_csv: Output CSV file path
    """
    try:
        # Read XML from file
        with open(xml_input_file, 'r', encoding='utf-8') as f:
            xml_string = f.read()
        
        # Check if file is empty or has invalid content
        if not xml_string.strip():
            print("Error: XML file is empty")
            sys.exit(1)
        
        # Remove leading dashes from XML lines (common in some exports)
        # This handles cases like "- <Event>" or " - <System>"
        lines = xml_string.split('\n')
        cleaned_lines = []
        for line in lines:
            # Remove leading "- " or " - " from each line
            cleaned_line = line.lstrip()
            if cleaned_line.startswith('- '):
                cleaned_line = cleaned_line[2:]
            cleaned_lines.append(cleaned_line)
        xml_string = '\n'.join(cleaned_lines)
        
        # Check if it's a multi-event XML (wrapped in root element)
        if not xml_string.strip().startswith('<Event'):
            # Try to wrap it or find Event elements
            try:
                # Parse as-is first
                root = ET.fromstring(xml_string)
                # Find all Event elements
                events = root.findall('.//{http://schemas.microsoft.com/win/2004/08/events/event}Event')
                if not events:
                    events = root.findall('.//Event')
                if events:
                    xml_string = ET.tostring(events[0], encoding='unicode')
            except:
                pass
        
        # Parse the XML
        csv_data = parse_event_xml(xml_string)
        
        # Write to CSV
        fieldnames = ['eventdate', 'hostname', 'user', 'processid', 'image', 'processcommandline', 'hashes']
        
        with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerow(csv_data)
        
        print(f"✓ CSV file created: {output_csv}")
        print(f"\nParsed data:")
        for key, value in csv_data.items():
            print(f"  {key}: {value}")
        
        return csv_data
    
    except FileNotFoundError:
        print(f"Error: File '{xml_input_file}' not found.")
        sys.exit(1)
    except ET.ParseError as e:
        print(f"Error: Failed to parse XML - {e}")
        print("\nPlease check that your XML file:")
        print("  1. Starts with <Event xmlns=...>")
        print("  2. Has proper XML structure")
        print("  3. Is encoded in UTF-8")
        print("\nFirst 200 characters of file:")
        try:
            with open(xml_input_file, 'r', encoding='utf-8') as f:
                print(repr(f.read(200)))
        except:
            pass
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

# Main execution
if __name__ == "__main__":
    # Default input file
    input_file = 'xmldata'
    output_file = 'output.csv'
    
    # Check for command line arguments
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    if len(sys.argv) > 2:
        output_file = sys.argv[2]
    
    print(f"Reading XML from: {input_file}")
    print(f"Writing CSV to: {output_file}\n")
    
    # Convert XML to CSV
    xml_to_csv(input_file, output_file)

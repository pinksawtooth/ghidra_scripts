# struct_typer.py
# @category Analysis

import re
import sys
import logging
from ghidra.program.model.data import Structure, PointerDataType, FunctionDefinition
from ghidra.util.task import TaskMonitor
from ghidra.app.services import DataTypeManagerService
from ghidra.framework.plugintool import PluginTool
from ghidra.program.model.symbol import SourceType

# Swing Imports for GUI
from javax.swing import (JDialog, JPanel, JLabel, JTextField, JCheckBox, 
                         JRadioButton, ButtonGroup, JButton, JList, JScrollPane, 
                         BorderFactory, BoxLayout, JComboBox, DefaultListModel)
from java.awt import BorderLayout, GridLayout, FlowLayout, Dimension
from javax.swing.border import EmptyBorder

# Setup Logger
logger = logging.getLogger("struct_typer")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

g_DefaultPrefixRegexp = r'field_.*_'

class StructTyperDialog:
    def __init__(self, tool, structures):
        self.tool = tool
        self.structures = sorted(structures, key=lambda s: s.getName())
        self.accepted = False
        
        self.dialog = JDialog()
        self.dialog.setTitle("Struct Typer (Ghidra)")
        self.dialog.setModal(True)
        self.dialog.setSize(500, 400)
        self.dialog.setLayout(BorderLayout())
        
        # --- Main Content ---
        content_panel = JPanel(BorderLayout(10, 10))
        content_panel.setBorder(EmptyBorder(10, 10, 10, 10))
        
        # 1. Mode Selection (Structure vs Stack Frame)
        mode_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        mode_panel.setBorder(BorderFactory.createTitledBorder("Mode"))
        
        self.rb_struct = JRadioButton("Structure", True)
        self.rb_stack = JRadioButton("Stack Frame")
        
        group = ButtonGroup()
        group.add(self.rb_struct)
        group.add(self.rb_stack)
        
        mode_panel.add(self.rb_struct)
        mode_panel.add(self.rb_stack)
        
        content_panel.add(mode_panel, BorderLayout.NORTH)
        
        # 2. Structure List
        list_panel = JPanel(BorderLayout(5, 5))
        list_panel.setBorder(BorderFactory.createTitledBorder("Select Structure"))
        
        self.struct_model = DefaultListModel()
        for s in self.structures:
            self.struct_model.addElement(s.getName())
            
        self.list_structs = JList(self.struct_model)
        scroll_pane = JScrollPane(self.list_structs)
        list_panel.add(scroll_pane, BorderLayout.CENTER)
        
        content_panel.add(list_panel, BorderLayout.CENTER)
        
        # 3. Member Filter Options
        options_panel = JPanel(GridLayout(2, 1, 5, 5))
        options_panel.setBorder(BorderFactory.createTitledBorder("Member Name Filter"))
        
        self.cb_use_regex = JCheckBox("Use Regex Prefix", False)
        self.tf_regex = JTextField(g_DefaultPrefixRegexp)
        
        row1 = JPanel(FlowLayout(FlowLayout.LEFT))
        row1.add(self.cb_use_regex)
        row1.add(self.tf_regex)
        options_panel.add(row1)
        
        content_panel.add(options_panel, BorderLayout.SOUTH)
        
        self.dialog.add(content_panel, BorderLayout.CENTER)
        
        # --- Buttons ---
        btn_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        btn_run = JButton("Run")
        btn_run.addActionListener(lambda e: self.on_run())
        btn_cancel = JButton("Cancel")
        btn_cancel.addActionListener(lambda e: self.on_cancel())
        
        btn_panel.add(btn_run)
        btn_panel.add(btn_cancel)
        
        self.dialog.add(btn_panel, BorderLayout.SOUTH)
        
        # Listeners for mode change
        self.rb_struct.addActionListener(lambda e: self.toggle_list(True))
        self.rb_stack.addActionListener(lambda e: self.toggle_list(False))
        
    def toggle_list(self, enable):
        self.list_structs.setEnabled(enable)

    def on_run(self):
        self.accepted = True
        self.dialog.setVisible(False)
        
    def on_cancel(self):
        self.accepted = False
        self.dialog.setVisible(False)
    
    def setVisible(self, visible):
        self.dialog.setVisible(visible)




from java.util import ArrayList

class StructTyperRunner:
    def __init__(self):
        self.dtm_service = state.getTool().getService(DataTypeManagerService)
        self.program = currentProgram
        
    def get_all_structures(self):
        """Returns a list of all structures in the current program's DTM."""
        structs = []
        dtm = self.program.getDataTypeManager()
        # Recursive or flat? standard getAllStructures returns an iterator
        it = dtm.getAllStructures()
        while it.hasNext():
            structs.append(it.next())
        return structs

    def find_type(self, name):
        """
        Searches for a DataType with the given name across all open DataTypeManagers.
        Prioritizes FunctionDefinitions if possible, but the original script just grabbed 'named type'.
        Returns the first match, or None.
        """
        # 1. Search in current program
        # 2. Search in other open archives
        managers = [self.program.getDataTypeManager()]
        if self.dtm_service:
            managers.extend(self.dtm_service.getDataTypeManagers())
            
        for mgr in managers:
            # We want an exact match for the name
            # findDataTypes populates a list
            types = ArrayList()
            mgr.findDataTypes(name, types)
            
            for dt in types:
                if dt.getName() == name:
                    return dt
        return None

    def strip_numbered_name(self, name):
        """Remove trailing unique ID like IDA does (e.g. _1, _2)."""
        # Original logic: 
        # idx = len(name) - 1
        # while idx >= 0: ...
        # Simplified regex approach
        # Look for _[0-9]+$
        m = re.search(r'_(\d+)$', name)
        if m:
            return name[:m.start()]
        return name

    def filter_name(self, name, regex_prefix):
        """Applies filter to strip prefix."""
        # First strip number suffix
        base_name = self.strip_numbered_name(name)
        
        if regex_prefix:
            # Original logic:
            # reg = re.compile('('+regPrefix+')(.*)')
            # m = reg.match(funcname)
            # if m: return m.group(2)
            try:
                m = re.match(f"({regex_prefix})(.*)", base_name)
                if m:
                    logger.debug(f"Stripping prefix: {name} -> {m.group(2)}")
                    return m.group(2)
            except Exception as e:
                logger.error(f"Regex error: {e}")
        
        return base_name

    def process_structure(self, struct, regex_prefix):
        """
        Iterates structure components, finds types, and updates them.
        """
        logger.info(f"Processing structure: {struct.getName()}")
        count = 0
        
        # We need to be careful modifying the structure while iterating? 
        # Structure.getComponents() returns an array, so it's a snapshot.
        components = struct.getComponents() 
        
        for comp in components:
            member_name = comp.getFieldName()
            if not member_name:
                continue
                
            search_name = self.filter_name(member_name, regex_prefix)
            if not search_name or search_name == member_name and regex_prefix:
                # If we demanded a prefix match and didn't get one (and didn't change name), maybe skip?
                # Original script logic: if m is None: pass (continues with original name)
                pass

            target_type = self.find_type(search_name)
            if target_type:
                # Found a type! 
                # Original script checks if it's a function (BT_FUNC) and if so makes a pointer.
                # In Ghidra, if we find a FunctionDefinition, we usually want a Pointer to it.
                # If we find a Structure, we might want a Pointer to it too, or the Struct itself?
                # The prompt says "struct_typer" -> "Attempts to set types for struct members based on searching for like-named types".
                # Original: `if not tif.is_func(): continue; tif.create_ptr(tif)`
                # So it ONLY handled function pointers.
                
                is_func = isinstance(target_type, FunctionDefinition)
                if not is_func:
                    logger.debug(f"Found type {target_type.getName()} but it is not a function. Skipping.")
                    continue
                
                logger.info(f"Found match: {member_name} -> {target_type.getName()}")
                
                # Create pointer
                ptr_type = PointerDataType(target_type)
                
                # Update structure
                # struct.replace(int index, DataType dataType, int length, String name, String comment)
                # We need the index. comp.getOrdinal() ?
                try:
                    ordinal = comp.getOrdinal()
                    # We must ensure we are replacing the right thing.
                    # replaceAtOffset might be safer if ordinal shifted? But strict iteration is ok if we don't change size?
                    # Pointer is usually 4/8 bytes. If original was undefined4, size is same.
                    struct.replace(ordinal, ptr_type, -1, member_name, comp.getComment())
                    count += 1
                except Exception as e:
                    logger.error(f"Failed to replace member {member_name}: {e}")

        if count > 0:
            # Commit changes to the DataTypeManager?
            # Usually struct.replace updates the structure. 
            # If it's in a DTM, we might need to save it?
            # Structure changes are immediate if it's obtained from DTM.
            pass
            
        return count

    def process_stack_frame(self, func, regex_prefix):
        """
        Iterates stack variables, finds types, and updates them.
        """
        logger.info(f"Processing stack frame for: {func.getName()}")
        count = 0
        
        # Get all variables (params + locals)
        # We need the high-level variables? Or the stack frame properties?
        # func.getAllVariables() returns LocalVariable, Parameter, etc.
        vars = func.getAllVariables()
        
        for var in vars:
            if not var.isStackVariable():
                continue
                
            var_name = var.getName()
            search_name = self.filter_name(var_name, regex_prefix)
            
            target_type = self.find_type(search_name)
            if target_type:
                is_func = isinstance(target_type, FunctionDefinition)
                if not is_func:
                    continue

                logger.info(f"Found match: {var_name} -> {target_type.getName()}")
                ptr_type = PointerDataType(target_type)
                
                try:
                    # setDataType(DataType type, SourceType source)
                    var.setDataType(ptr_type, SourceType.USER_DEFINED)
                    count += 1
                except Exception as e:
                    logger.error(f"Failed to set type for var {var_name}: {e}")
                    
        return count

    def run(self):
        structs = self.get_all_structures()
        dialog = StructTyperDialog(state.getTool(), structs)
        dialog.setVisible(True)
        
        if not dialog.accepted:
            logger.info("Cancelled.")
            return

        regex_prefix = ""
        if dialog.cb_use_regex.isSelected():
            regex_prefix = dialog.tf_regex.getText()
            # Basic validation of regex
            try:
                re.compile(regex_prefix)
            except:
                print("Invalid Regex")
                return

        # Start Transaction
        tid = self.program.startTransaction("Struct Typer Analysis")
        try:
            if dialog.rb_struct.isSelected():
                sel_indices = dialog.list_structs.getSelectedIndices()
                if not sel_indices:
                    print("No structure selected.")
                    return
                
                # Get selected struct
                # We need to map back from model or list
                # Since we filtered, model index != structs index
                # But we stored names in model.
                # Let's find struct by name from the selected value
                sel_val = dialog.list_structs.getSelectedValue()
                target_struct = None
                for s in structs:
                    if s.getName() == sel_val:
                        target_struct = s
                        break
                
                if target_struct:
                    num = self.process_structure(target_struct, regex_prefix)
                    print(f"Updated {num} members in {target_struct.getName()}")
                    
            else:
                # Stack Frame Mode
                func = self.program.getFunctionManager().getFunctionContaining(currentAddress)
                if not func:
                    print("No function at current address.")
                else:
                    num = self.process_stack_frame(func, regex_prefix)
                    print(f"Updated {num} variables in {func.getName()}")
                    
        except Exception as e:
            logger.error(f"Error during processing: {e}")
        finally:
            self.program.endTransaction(tid, True) # Commit

if __name__ == "__main__":
    runner = StructTyperRunner()
    runner.run()

pageextension 80100 "FLA Customer List Ext" extends "Customer List"
{
    layout
    {

    }
    actions
    {
        addlast(Reporting)
        {
            action("Test Message Action")
            {
                ApplicationArea = All;
                Caption = 'Test Message Action';
                ToolTip = 'Show a test message';
                Image = Warning;
                trigger OnAction()
                begin
                    Message('This is a test message from the FLACustomerListExt page extension.');
                end;
            }
        }
    }
}
program aes_256;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  {$IFDEF HASAMIGA}
  athreads,
  {$ENDIF}
  Interfaces, // this includes the LCL widgetset
  Forms, AES_256_Lab_Main, uAES256, uSHA256, uAES256_ECB, uAES256_CBC,
  uAES256_Container, Fixis
  { you can add units after this };

{$R *.res}

begin
  RequireDerivedFormResource:=True;
  Application.Title:='AES_256_Lab ';
  Application.Scaled:=True;
  Application.Initialize;
  Application.CreateForm(TAES_256_Lab, AES_256_Lab);
  Application.Run;
end.


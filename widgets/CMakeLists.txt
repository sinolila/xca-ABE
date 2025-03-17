list(APPEND xca_sources
    KeyDetail.cpp		NewKey.cpp		XcaApplication.h
    KeyDetail.h		NewKey.h		XcaDialog.cpp
    KeyTreeView.cpp		XcaDialog.h		XcaHeaderView.cpp
    KeyTreeView.h		XcaHeaderView.h
    MW_help.cpp		XcaProxyModel.cpp
    MW_menu.cpp		XcaProxyModel.h		XcaTreeView.cpp
    MainWindow.cpp		XcaTreeView.h		XcaWarning.cpp
    MainWindow.h		XcaWarning.h
    ExportDialog.cpp	OpenDb.cpp		clicklabel.cpp
    ExportDialog.h		OpenDb.h		clicklabel.h
    FocusCombo.h		Options.cpp		
    Help.cpp		Options.h
    Help.h			PwDialog.cpp		
    ImportMulti.cpp		PwDialog.h
    ImportMulti.h		SearchPkcs11.cpp
    ItemCombo.h		SearchPkcs11.h	hashBox.cpp
    OidResolver.cpp		hashBox.h		kvView.cpp
    OidResolver.h		kvView.h		
    XcaApplication.cpp	validity.cpp
    pkcs12EncBox.h          validity.h
    pkcs12EncBox.cpp        XcaDetail.h
                            XcaDetail.cpp
    stubs.cpp
)

list(TRANSFORM xca_sources PREPEND ${PROJECT_SOURCE_DIR}/widgets/)
target_sources(xcalib PRIVATE ${xca_sources})

cmake_minimum_required(VERSION 3.16)

project(VisualSafety VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 REQUIRED COMPONENTS Quick)

qt_standard_project_setup(REQUIRES 6.8)

qt_add_executable(appVisualSafety
    src/main.cpp
    src/core/appconfig.cpp
    src/core/securitycontroller.cpp
    src/core/securitycontroller_collectors.cpp
    src/core/thememanager.cpp
    src/icons/emojiicons.cpp
)

qt_add_qml_module(appVisualSafety
    URI VisualSafety
    QML_FILES
        qml/Main.qml
        qml/components/MetricCard.qml
        qml/components/SectionCard.qml
        qml/components/StatusTag.qml
        qml/components/ThemedButton.qml
        qml/components/ThemedTextField.qml
        qml/components/ThemedSwitch.qml
        qml/components/ThemedComboBox.qml
        qml/components/I18n.qml
        qml/components/qmldir
        qml/pages/ActionsPage.qml
        qml/pages/AlertsPage.qml
        qml/pages/AppsPage.qml
        qml/pages/CredentialsPage.qml
        qml/pages/LogsPage.qml
        qml/pages/NetworkPage.qml
        qml/pages/PublicPage.qml
        qml/pages/PluginRuntimePage.qml
        qml/pages/PluginsPage.qml
        qml/pages/OverviewPage.qml
        qml/pages/PermissionsPage.qml
        qml/pages/PortsPage.qml
    SOURCES
        src/core/appconfig.h
        src/core/securitycontroller.h
        src/core/thememanager.h
        src/icons/emojiicons.h
)

# Qt for iOS sets MACOSX_BUNDLE_GUI_IDENTIFIER automatically since Qt 6.1.
# If you are developing for iOS or macOS you should consider setting an
# explicit, fixed bundle identifier manually though.
set_target_properties(appVisualSafety PROPERTIES
#    MACOSX_BUNDLE_GUI_IDENTIFIER com.example.appVisualSafety
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

target_link_libraries(appVisualSafety
    PRIVATE Qt6::Quick
)

if (WIN32)
    target_sources(appVisualSafety PRIVATE src/icons/app_icon.rc)
    target_link_libraries(appVisualSafety PRIVATE dwmapi)
endif()

include(GNUInstallDirs)
install(TARGETS appVisualSafety
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

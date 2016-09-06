#include <QtWidgets>

#include "window.h"
#include <QDebug>

#include <fstream>
#include <vector>
#include <string>

typedef unsigned char BYTE;

Window::Window(QWidget *parent)
    : QWidget(parent)
{
    browseButton = createButton(tr("&Browse..."), SLOT(browse()));
    directoryComboBox = createComboBox(QDir::currentPath());
    directoryLabel = new QLabel(tr("Select file:"));
    scanButton = createButton(tr("&Scan"), SLOT(scan()));
    connect(scanButton, &QAbstractButton::clicked, this, &Window::find);

    createFilesTable();

    QGridLayout *mainLayout = new QGridLayout;
    mainLayout->addWidget(directoryLabel, 2, 0);
    mainLayout->addWidget(directoryComboBox, 2, 1);
    mainLayout->addWidget(browseButton, 2, 2);
    mainLayout->addWidget(scanButton, 4, 1, Qt::AlignHCenter);
    mainLayout->addWidget(filesTable, 3, 0, 1, 3);
    setLayout(mainLayout);

    setWindowTitle(tr("Evosec"));
    resize(700, 300);
}

void Window::browse()
{
    QString directory = QFileDialog::getOpenFileName(this,
                               tr("Find Files"), directoryComboBox->currentText());

    if (!directory.isEmpty()) {
        if (directoryComboBox->findText(directory) == -1)
            directoryComboBox->addItem(directory);
        directoryComboBox->setCurrentIndex(directoryComboBox->findText(directory));
    }
}

QPushButton *Window::createButton(const QString &text, const char *member)
{
    QPushButton *button = new QPushButton(text);
    connect(button, SIGNAL(clicked()), this, member);
    return button;
}

void Window::loadEngine() {
    engine = Engine(BASE_PATH);
}

void Window::showEvent(QShowEvent *)
{
    QTimer::singleShot(50, this, SLOT(loadEngine()));
}

QComboBox *Window::createComboBox(const QString &text)
{
    QComboBox *comboBox = new QComboBox;
    comboBox->setEditable(true);
    comboBox->addItem(text);
    comboBox->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    return comboBox;
}

void Window::createFilesTable()
{
    filesTable = new QTableWidget(0, 2);
    filesTable->setSelectionBehavior(QAbstractItemView::SelectRows);

    QStringList labels;
    labels << tr("Filename") << tr("Verdict");
    filesTable->setHorizontalHeaderLabels(labels);
    filesTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    filesTable->verticalHeader()->hide();
    filesTable->setShowGrid(false);
}

std::vector<BYTE> readFile(const std::string &path)
{
    std::ifstream file(path.c_str(), std::ios::binary);

    return std::vector<BYTE>((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());
}


void Window::scan()
{
    QString path = directoryComboBox->currentText();
    std::vector<BYTE> input = readFile(path.toStdString());

    QString fileName = QFileInfo(path).fileName();
    QTableWidgetItem *fileNameItem = new QTableWidgetItem(path);
    const QString toolTip = QDir::toNativeSeparators(fileName);

    fileNameItem->setText(fileName);
    fileNameItem->setToolTip(toolTip);
    fileNameItem->setFlags(fileNameItem->flags() ^ Qt::ItemIsEditable);
    QTableWidgetItem *verdictItem = new QTableWidgetItem;

    std::string verdict = engine.Check(input);
    verdictItem->setText(QString::fromStdString(verdict));
    verdictItem->setToolTip(toolTip);
    verdictItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    verdictItem->setFlags(verdictItem->flags() ^ Qt::ItemIsEditable);

    int row = filesTable->rowCount();
    filesTable->insertRow(row);
    filesTable->setItem(row, 0, fileNameItem);
    filesTable->setItem(row, 1, verdictItem);
}

